// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * 039_nc_ipam_contract.c - IP table read contract, import pipeline and static
 *                          reservation transaction for the client-details page.
 *
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>
 *
 * Why this is a separate fragment rather than more lines inside
 * 013_nc_network_services.c: 013 owns the existing IPAM transaction authority
 * and is touched by other work; everything the frontend handoff asks for on top
 * of it is additive.  Keeping it here means 013 gains exactly one call site.
 *
 * What this file deliberately does NOT claim:
 *
 *   - It does not pretend a DHCP lease is bound the moment a reservation is
 *     written.  dnsmasq only hands the new address to the client on its next
 *     renew, which can be hours away, so `lease_readback` reports
 *     available=false with a stable reason instead of echoing the requested
 *     address back as if it were observed.
 *   - Capabilities are derived from probes (config file writability, init
 *     script presence, table readability), never from a build-time constant.
 *     A box where /etc/config/dhcp cannot be written reports
 *     ip_table_static_reservation_write.available=false with
 *     runtime_executor_unavailable, and the frontend is then required by its own
 *     contract to keep the button disabled.
 */

#define NC_IPAMC_PREVIEW_TTL_S 1800
#define NC_IPAMC_ROWS_MAX 1000
#define NC_IPAMC_CSV_MAX (256 * 1024)

static void nc_ipamc_db_init(void)
{
    /*
     * ipam_import_job already exists in 013 and its columns are consumed by
     * jmx_bulk_ip_get().  Rather than ALTER a table another fragment reads, the
     * three-phase pipeline keeps its own state beside it, keyed by the same job
     * id.  That also means a downgrade to an older binary leaves the legacy
     * job list intact instead of tripping over unknown columns.
     */
    nc_exec("CREATE TABLE IF NOT EXISTS ipam_import_preview ("
            "id TEXT PRIMARY KEY,network_id TEXT NOT NULL,revision INTEGER NOT NULL DEFAULT 0,"
            "rows_total INTEGER DEFAULT 0,rows_valid INTEGER DEFAULT 0,rows_invalid INTEGER DEFAULT 0,"
            "payload_json TEXT NOT NULL DEFAULT '[]',summary_json TEXT NOT NULL DEFAULT '{}',"
            "created_at INTEGER NOT NULL DEFAULT 0,expires_at INTEGER NOT NULL DEFAULT 0)");
    nc_exec("CREATE TABLE IF NOT EXISTS ipam_import_job_state ("
            "job_id TEXT PRIMARY KEY,preview_id TEXT DEFAULT '',request_id TEXT DEFAULT '',"
            "network_id TEXT DEFAULT '',status TEXT NOT NULL DEFAULT 'queued',"
            "error TEXT DEFAULT '',results_json TEXT NOT NULL DEFAULT '[]',"
            "revision_before INTEGER DEFAULT 0,revision_after INTEGER DEFAULT 0,"
            "created_at INTEGER NOT NULL DEFAULT 0,updated_at INTEGER NOT NULL DEFAULT 0)");
    /*
     * Idempotency ledger.  request_id is the PRIMARY KEY, so a replay is a
     * lookup rather than a re-apply, and the stored envelope is returned
     * verbatim -- a client that retries after a dropped response gets the same
     * answer instead of a second write or a spurious conflict.
     */
    nc_exec("CREATE TABLE IF NOT EXISTS ipam_write_request ("
            "request_id TEXT PRIMARY KEY,kind TEXT NOT NULL DEFAULT '',"
            "network_id TEXT DEFAULT '',fingerprint TEXT DEFAULT '',"
            "response_json TEXT NOT NULL DEFAULT '{}',created_at INTEGER NOT NULL DEFAULT 0)");
    nc_exec("CREATE INDEX IF NOT EXISTS idx_ipam_import_job_state_status ON ipam_import_job_state(status)");
    nc_exec("CREATE INDEX IF NOT EXISTS idx_ipam_write_request_kind ON ipam_write_request(kind)");
}

static void nc_ipamc_iso8601(int64_t epoch, char *out, size_t out_len)
{
    struct tm tm;
    time_t t = (time_t)epoch;
    if (!out || !out_len) return;
    out[0] = '\0';
    if (epoch <= 0) return;
    if (!gmtime_r(&t, &tm)) return;
    if (strftime(out, out_len, "%Y-%m-%dT%H:%M:%SZ", &tm) == 0) out[0] = '\0';
}

/* json_object_object_add() consumes a reference; a value shared by many rows
 * therefore needs one extra reference per row or the second add frees it. */
static void nc_ipamc_add_shared(struct json_object *target, const char *key,
                                struct json_object *shared)
{
    if (!target || !key) return;
    json_object_object_add(target, key,
                           shared ? json_object_get(shared) : NULL);
}

static void nc_ipamc_add_str_or_null(struct json_object *o, const char *key,
                                     const char *value)
{
    if (!o || !key) return;
    json_object_object_add(o, key, (value && value[0]) ?
                           json_object_new_string(value) : NULL);
}

static void nc_ipamc_cap_add(struct json_object *caps, const char *name,
                             int available, const char *reason, const char *scope)
{
    struct json_object *entry;
    if (!caps || !name) return;
    entry = json_object_new_object();
    json_object_object_add(entry, "available", json_object_new_boolean(available != 0));
    /*
     * reason is null exactly when available is true.  A capability that is
     * unavailable always carries a machine-stable code, because the frontend
     * contract renders the code and must not fall back to a generic message.
     */
    json_object_object_add(entry, "reason",
                           available ? NULL :
                           json_object_new_string(reason && reason[0] ? reason : "source_unavailable"));
    json_object_object_add(entry, "scope",
                           (scope && scope[0]) ? json_object_new_string(scope) : NULL);
    json_object_object_add(caps, name, entry);
}

static void nc_ipamc_field_add(struct json_object *fields, const char *name,
                               int supported, const char *reason)
{
    struct json_object *entry;
    if (!fields || !name) return;
    entry = json_object_new_object();
    json_object_object_add(entry, "supported", json_object_new_boolean(supported != 0));
    json_object_object_add(entry, "reason",
                           supported ? NULL :
                           json_object_new_string(reason && reason[0] ? reason : "field_not_supported"));
    json_object_object_add(fields, name, entry);
}

/*
 * The local DNS suffix.  Per-scope domain wins when set; otherwise dnsmasq's
 * own `domain` option.  Read through UCI because that is where dnsmasq actually
 * reads it from -- deriving it from the DB would report what we intended rather
 * than what is live.  Cached briefly: jmx_bulk_ip_get() also runs as the
 * readback of every write, so an uncached read would parse /etc/config/dhcp
 * several times per request.
 */
static int nc_ipamc_local_domain(char *out, size_t out_len)
{
    static char cached[128];
    static int64_t cached_at;
    static int cached_ok;
    struct uci_context *ctx = NULL;
    struct uci_ptr ptr;
    char key[64];
    int64_t now = nc_now_s();

    if (!out || !out_len) return 0;
    out[0] = '\0';
    if (cached_at && now - cached_at < 10) {
        if (cached_ok) snprintf(out, out_len, "%s", cached);
        return cached_ok;
    }
    cached_at = now;
    cached_ok = 0;
    cached[0] = '\0';
    ctx = uci_alloc_context();
    if (!ctx) return 0;
    memset(&ptr, 0, sizeof(ptr));
    snprintf(key, sizeof(key), "dhcp.@dnsmasq[0].domain");
    if (uci_lookup_ptr(ctx, &ptr, key, true) == UCI_OK && ptr.o &&
        ptr.o->type == UCI_TYPE_STRING && ptr.o->v.string && ptr.o->v.string[0]) {
        snprintf(cached, sizeof(cached), "%s", ptr.o->v.string);
        cached_ok = 1;
    }
    uci_free_context(ctx);
    if (cached_ok) snprintf(out, out_len, "%s", cached);
    return cached_ok;
}

/*
 * Two indexes built with one query each, so decorating N addresses stays two
 * statements instead of 2N.  json-c objects are hash tables, so the per-row
 * lookup is a hash probe.
 */
static struct json_object *nc_ipamc_lease_index(void)
{
    struct json_object *idx = json_object_new_object();
    sqlite3_stmt *st = NULL;
    if (nc_prepare(&st, "SELECT mac,ip,hostname,expires_at,online FROM dhcp_lease_cache") != 0)
        return idx;
    while (sqlite3_step(st) == SQLITE_ROW) {
        const char *mac = (const char *)sqlite3_column_text(st, 0);
        char macn[32] = "";
        struct json_object *row;
        if (!mac || !mac[0] || !nc_mac_normalize(mac, macn, sizeof(macn))) continue;
        row = json_object_new_object();
        nc_add_text(row, "ip", st, 1);
        nc_add_text(row, "hostname", st, 2);
        json_object_object_add(row, "expires_at", json_object_new_int64(sqlite3_column_int64(st, 3)));
        json_object_object_add(row, "online", json_object_new_boolean(sqlite3_column_int(st, 4)));
        json_object_object_add(idx, macn, row);
    }
    sqlite3_finalize(st);
    return idx;
}

/*
 * Runtime write reachability.  Both halves are probed, because they fail
 * independently and the frontend needs to know which: an unwritable
 * /etc/config/dhcp is a filesystem/permission problem, a missing dnsmasq init
 * script means the projection would be committed and never applied.
 */
static int nc_ipamc_runtime_writable(const char **reason)
{
    if (!nc_adv_path_writable("/etc/config/dhcp")) {
        if (reason) *reason = nc_file_exists("/etc/config/dhcp") ?
                              "permission_denied" : "runtime_executor_unavailable";
        return 0;
    }
    if (!nc_file_exists("/etc/init.d/dnsmasq")) {
        if (reason) *reason = "runtime_executor_unavailable";
        return 0;
    }
    if (reason) *reason = NULL;
    return 1;
}

static struct json_object *nc_ipamc_reservation_index(void)
{
    struct json_object *idx = json_object_new_object();
    sqlite3_stmt *st = NULL;
    if (nc_prepare(&st, "SELECT mac,ip,name FROM dhcp_reservation WHERE enabled=1") != 0)
        return idx;
    while (sqlite3_step(st) == SQLITE_ROW) {
        const char *mac = (const char *)sqlite3_column_text(st, 0);
        char macn[32] = "";
        struct json_object *row;
        if (!mac || !mac[0] || !nc_mac_normalize(mac, macn, sizeof(macn))) continue;
        row = json_object_new_object();
        nc_add_text(row, "ip", st, 1);
        nc_add_text(row, "name", st, 2);
        json_object_object_add(idx, macn, row);
    }
    sqlite3_finalize(st);
    return idx;
}

static struct json_object *nc_ipamc_idx_get(struct json_object *idx,
                                            const char *macn, const char *key)
{
    struct json_object *row = NULL, *v = NULL;
    if (!idx || !macn || !macn[0]) return NULL;
    if (!json_object_object_get_ex(idx, macn, &row) || !row) return NULL;
    if (!key) return row;
    if (!json_object_object_get_ex(row, key, &v)) return NULL;
    return v;
}

/*
 * One address record.  Every field added here is either observed or explicitly
 * null with a reason -- there is no branch that invents a value.  `shared_net`
 * is the network descriptor the frontend joins on; it is reference-counted
 * rather than rebuilt per row.
 */
static void nc_ipamc_decorate_address(struct json_object *o,
                                      struct json_object *shared_net,
                                      struct json_object *leases,
                                      struct json_object *reservations,
                                      const char *domain)
{
    const char *ip = nc_json_str_def(o, "ip", "");
    const char *mac = nc_json_str_def(o, "mac", "");
    const char *hostname = nc_json_str_def(o, "hostname", "");
    const char *owner = nc_json_str_def(o, "owner", "");
    char macn[32] = "";
    int have_mac = mac[0] && nc_mac_normalize(mac, macn, sizeof(macn));
    struct json_object *res = have_mac ? nc_ipamc_idx_get(reservations, macn, NULL) : NULL;
    struct json_object *lease = have_mac ? nc_ipamc_idx_get(leases, macn, NULL) : NULL;
    struct json_object *join = json_object_new_object();
    struct json_object *dns = json_object_new_object();
    const char *res_name = res ? nc_json_str_def(res, "name", "") : "";
    int64_t expires = 0;

    nc_ipamc_add_shared(o, "network", shared_net);
    /* `address` is the name the page binds to; `ip` stays for existing callers. */
    json_object_object_add(o, "address", json_object_new_string(ip));
    nc_ipamc_add_str_or_null(o, "name",
                             res_name[0] ? res_name : (owner[0] ? owner : NULL));
    json_object_object_add(o, "name_source",
                           res_name[0] ? json_object_new_string("dhcp_reservation") :
                           (owner[0] ? json_object_new_string("ipam_owner") : NULL));

    /*
     * local_dns is only claimed when both halves exist.  dnsmasq answers
     * <hostname>.<domain> for a host it knows; with no hostname there is
     * nothing to answer, and with no `domain` option there is no suffix, so
     * either gap makes the name a guess rather than a fact.
     */
    if (hostname[0] && domain && domain[0]) {
        char fqdn[256];
        snprintf(fqdn, sizeof(fqdn), "%s.%s", hostname, domain);
        json_object_object_add(dns, "available", json_object_new_boolean(1));
        json_object_object_add(dns, "name", json_object_new_string(fqdn));
        json_object_object_add(dns, "reason", NULL);
    } else {
        json_object_object_add(dns, "available", json_object_new_boolean(0));
        json_object_object_add(dns, "name", NULL);
        json_object_object_add(dns, "reason", json_object_new_string(
            hostname[0] ? "local_dns_domain_not_configured" : "record_has_no_hostname"));
    }
    json_object_object_add(o, "local_dns", dns);

    /*
     * lease_type is derived from the two runtime sources, not from the stored
     * `type`/`source` columns: a row can be created by an import long before
     * dnsmasq has ever seen the client.  static wins over dynamic because a
     * reservation is what the address will be on the next renew.
     */
    if (res) {
        json_object_object_add(o, "lease_type", json_object_new_string("static"));
        json_object_object_add(o, "lease_type_reason", NULL);
    } else if (lease) {
        json_object_object_add(o, "lease_type", json_object_new_string("dynamic"));
        json_object_object_add(o, "lease_type_reason", NULL);
    } else {
        json_object_object_add(o, "lease_type", NULL);
        json_object_object_add(o, "lease_type_reason", json_object_new_string(
            have_mac ? "no_lease_or_reservation_for_mac" : "record_has_no_mac"));
    }

    /*
     * A static reservation has no expiry, which is a different fact from "we
     * could not read one".  Both come back as expires_at=null, so the reason
     * carries the distinction the handoff asks for.
     */
    if (lease) {
        struct json_object *e = NULL;
        if (json_object_object_get_ex(lease, "expires_at", &e) && e)
            expires = json_object_get_int64(e);
    }
    if (expires > 0) {
        char iso[40];
        nc_ipamc_iso8601(expires, iso, sizeof(iso));
        nc_ipamc_add_str_or_null(o, "expires_at", iso);
        json_object_object_add(o, "expires_at_epoch", json_object_new_int64(expires));
        json_object_object_add(o, "expires_at_reason", NULL);
    } else {
        json_object_object_add(o, "expires_at", NULL);
        json_object_object_add(o, "expires_at_epoch", NULL);
        json_object_object_add(o, "expires_at_reason", json_object_new_string(
            res ? "static_reservation_has_no_expiry" :
            (lease ? "lease_has_no_expiry" : "no_lease_for_record")));
    }

    /*
     * The join contract, stated by the backend instead of guessed by the page.
     * Normalised MAC is the only stable cross-source key; a gateway or exclude
     * row has none, and there is no lease id to offer in its place, so it says
     * joinable=false rather than letting the frontend fall back to array index
     * or display name.
     */
    if (have_mac) {
        json_object_object_add(join, "joinable", json_object_new_boolean(1));
        json_object_object_add(join, "key", json_object_new_string("mac"));
        json_object_object_add(join, "value", json_object_new_string(macn));
        json_object_object_add(join, "target", json_object_new_string("/api/v1/clients"));
        json_object_object_add(join, "reason", NULL);
    } else {
        json_object_object_add(join, "joinable", json_object_new_boolean(0));
        json_object_object_add(join, "key", NULL);
        json_object_object_add(join, "value", NULL);
        json_object_object_add(join, "target", NULL);
        json_object_object_add(join, "reason",
                               json_object_new_string("no_stable_cross_source_key"));
    }
    json_object_object_add(o, "join", join);
}

/*
 * CREATE TABLE IF NOT EXISTS is idempotent but not free, and jmx_bulk_ip_get()
 * is also the readback of every write, so it runs several times per request.
 * The guard is only set once the database is actually open -- otherwise a GET
 * that arrives before init would mark the schema done and the tables would
 * never be created.
 */
static void nc_ipamc_db_once(void)
{
    static int done;
    if (done || !g_netconfig_db) return;
    done = 1;
    nc_ipamc_db_init();
}

static void nc_ipamc_join_contract(struct json_object *data)
{
    struct json_object *jc = json_object_new_object();
    struct json_object *forbidden = json_object_new_array();

    json_object_object_add(jc, "key", json_object_new_string("mac"));
    json_object_object_add(jc, "normalization",
                           json_object_new_string("lowercase_colon_separated"));
    json_object_object_add(jc, "target", json_object_new_string("/api/v1/clients"));
    json_object_object_add(jc, "target_key", json_object_new_string("mac"));
    /* Named so the frontend cannot read silence as permission to improvise. */
    json_object_array_add(forbidden, json_object_new_string("array_index"));
    json_object_array_add(forbidden, json_object_new_string("display_name"));
    json_object_array_add(forbidden, json_object_new_string("hostname"));
    json_object_object_add(jc, "forbidden_keys", forbidden);
    json_object_object_add(jc, "unjoinable_reason",
                           json_object_new_string("no_stable_cross_source_key"));
    json_object_object_add(data, "join_contract", jc);
}

/*
 * Non-static, and declared in jmx_netconfig_db.c's declaration zone, because
 * 013 is included before this fragment and calls into it.  Same arrangement as
 * nc_cpufreq_capabilities() in 038.
 */
void nc_ipam_contract_decorate(struct json_object *data)
{
    struct json_object *nets = NULL, *caps = NULL, *fields = NULL;
    struct json_object *leases = NULL, *reservations = NULL;
    char domain[128] = "";
    int have_domain, read_ok, lease_ok, write_ok, i, n;
    const char *write_reason = NULL;

    if (!data) return;
    nc_ipamc_db_once();
    read_ok = g_netconfig_db != NULL;
    lease_ok = read_ok && nc_table_exists("dhcp_lease_cache");
    write_ok = read_ok && nc_ipamc_runtime_writable(&write_reason);
    have_domain = nc_ipamc_local_domain(domain, sizeof(domain));

    leases = nc_ipamc_lease_index();
    reservations = nc_ipamc_reservation_index();

    if (json_object_object_get_ex(data, "networks", &nets) && nets &&
        json_object_is_type(nets, json_type_array)) {
        n = (int)json_object_array_length(nets);
        for (i = 0; i < n; i++) {
            struct json_object *net = json_object_array_get_idx(nets, i);
            struct json_object *addrs = NULL, *shared = NULL;
            int j, m;

            if (!net) continue;
            shared = json_object_new_object();
            nc_ipamc_add_str_or_null(shared, "id", nc_json_str_def(net, "id", ""));
            nc_ipamc_add_str_or_null(shared, "name", nc_json_str_def(net, "name", ""));
            nc_ipamc_add_str_or_null(shared, "subnet", nc_json_str_def(net, "subnet", ""));
            if (json_object_object_get_ex(net, "addresses", &addrs) && addrs &&
                json_object_is_type(addrs, json_type_array)) {
                m = (int)json_object_array_length(addrs);
                for (j = 0; j < m; j++)
                    nc_ipamc_decorate_address(json_object_array_get_idx(addrs, j),
                                              shared, leases, reservations,
                                              have_domain ? domain : NULL);
            }
            json_object_put(shared);
        }
    }

    /*
     * The seven capabilities the frontend gates its buttons on are added into
     * the existing `capabilities` object rather than a new one, so a client that
     * already reads the older boolean names keeps working; nothing is removed.
     */
    if (json_object_object_get_ex(data, "capabilities", &caps) && caps) {
        nc_ipamc_cap_add(caps, "ip_table_read", read_ok,
                         "source_unavailable", "config_db");
        /*
         * Preview's scope is not "no writes": it persists one row in
         * ipam_import_preview so commit can refer to a batch by id instead of
         * trusting the client to resend it.  What it must never touch is
         * /etc/config/dhcp, dnsmasq or ipam_address, and that is what the scope
         * string says.
         */
        nc_ipamc_cap_add(caps, "ip_table_import_preview", read_ok,
                         "source_unavailable", "no_dhcp_or_runtime_write");
        /*
         * Commit is a write with the same runtime component as a single
         * reservation -- it edits /etc/config/dhcp and restarts dnsmasq -- so it
         * is gated on write_ok too.  Gating it on read_ok alone would leave the
         * import button enabled on a box that can only reach the config half,
         * which is the disabled-button rule in the handoff.
         */
        nc_ipamc_cap_add(caps, "ip_table_import_commit", read_ok && write_ok,
                         read_ok ? (write_reason ? write_reason
                                                 : "runtime_executor_unavailable")
                                 : "source_unavailable",
                         "dhcp_uci_and_dnsmasq_runtime");
        nc_ipamc_cap_add(caps, "ip_table_import_job", read_ok,
                         "source_unavailable", "config_db");
        /*
         * The only capability with a runtime component.  It stays false on a
         * box where /etc/config/dhcp is unwritable or the dnsmasq init script
         * is absent, because writing the config there would produce a
         * config-only success -- exactly what the handoff forbids.
         */
        nc_ipamc_cap_add(caps, "ip_table_static_reservation_write",
                         read_ok && write_ok,
                         read_ok ? (write_reason ? write_reason
                                                 : "runtime_executor_unavailable")
                                 : "source_unavailable",
                         "dhcp_uci_and_dnsmasq_runtime");
        nc_ipamc_cap_add(caps, "ip_table_local_dns", have_domain,
                         "local_dns_domain_not_configured",
                         have_domain ? domain : NULL);
        nc_ipamc_cap_add(caps, "ip_table_lease_expiry", lease_ok,
                         "source_unavailable", "dhcp_lease_cache");
        /*
         * A reservation is applied to dnsmasq immediately, but the client keeps
         * its old address until its next DHCP renew, so the write cannot report
         * an observed lease.  Saying so here is what stops the page from
         * treating a successful write as a bound lease.
         */
        nc_ipamc_cap_add(caps, "ip_table_lease_binding_readback", 0,
                         "lease_binding_requires_client_renew", "dhcp_lease_cache");
        json_object_object_add(caps, "ip_table_write_endpoint",
                               json_object_new_string(
            "POST /api/v1/bulk-ip/static-reservations/transactions"));
    }

    /*
     * field_support is the third state the handoff asks for.  A field that is
     * present but empty appears in every record as null; a field that this build
     * cannot source at all appears here as supported=false.  Without this map
     * the two are indistinguishable and the page would render "未提供" for a
     * field that simply has no value on this row.
     */
    fields = json_object_new_object();
    nc_ipamc_field_add(fields, "network", 1, NULL);
    nc_ipamc_field_add(fields, "address", 1, NULL);
    nc_ipamc_field_add(fields, "mac", 1, NULL);
    nc_ipamc_field_add(fields, "hostname", 1, NULL);
    nc_ipamc_field_add(fields, "name", 1, NULL);
    nc_ipamc_field_add(fields, "status", 1, NULL);
    nc_ipamc_field_add(fields, "local_dns", have_domain,
                       "local_dns_domain_not_configured");
    nc_ipamc_field_add(fields, "lease_type", lease_ok, "source_unavailable");
    nc_ipamc_field_add(fields, "expires_at", lease_ok, "source_unavailable");
    json_object_object_add(data, "field_support", fields);

    nc_ipamc_join_contract(data);
    json_object_object_add(data, "local_domain",
                           have_domain ? json_object_new_string(domain) : NULL);

    json_object_put(leases);
    json_object_put(reservations);
}

/* ------------------------------------------------------------------------- */
/* Static reservation transaction                                            */
/* ------------------------------------------------------------------------- */

/*
 * The UCI host section is keyed on the MAC, not on the address.  dnsmasq
 * matches `config host` entries by MAC, so keying on the address would leave
 * the old section behind when a client is moved to a different IP and dnsmasq
 * would then hold two host entries for one MAC.
 */
static void nc_ipamc_host_section(const char *macn, char *out, size_t out_len)
{
    size_t i, j = 0;
    const char *prefix = "dwrt_ipam_";
    if (!out || !out_len) return;
    out[0] = '\0';
    for (i = 0; prefix[i] && j + 1 < out_len; i++) out[j++] = prefix[i];
    for (i = 0; macn && macn[i] && j + 1 < out_len; i++)
        out[j++] = (macn[i] == ':') ? '_' : macn[i];
    out[j] = '\0';
}

static int nc_ipamc_uci_get(const char *pkg, const char *section,
                            const char *option, char *out, size_t out_len)
{
    struct uci_context *ctx;
    struct uci_ptr ptr;
    char key[320];
    int ok = 0;

    if (!out || !out_len) return 0;
    out[0] = '\0';
    if (!pkg || !section || !option) return 0;
    if ((size_t)snprintf(key, sizeof(key), "%s.%s.%s", pkg, section, option) >= sizeof(key))
        return 0;
    ctx = uci_alloc_context();
    if (!ctx) return 0;
    memset(&ptr, 0, sizeof(ptr));
    if (uci_lookup_ptr(ctx, &ptr, key, true) == UCI_OK && ptr.o &&
        ptr.o->type == UCI_TYPE_STRING && ptr.o->v.string) {
        snprintf(out, out_len, "%s", ptr.o->v.string);
        ok = 1;
    }
    uci_free_context(ctx);
    return ok;
}

/*
 * Project one reservation into /etc/config/dhcp and restart dnsmasq.
 *
 * The caller owns `bak`: on failure it restores it and restarts dnsmasq again,
 * on success it cleans it up.  Keeping the backup outside this function is what
 * makes the rollback in the transaction below able to report whether the
 * restore itself worked, instead of collapsing both outcomes into one -1.
 */
static int nc_ipamc_host_apply(const char *macn, const char *ip, const char *name,
                               int remove, char *bak, size_t bak_len,
                               const char **stage)
{
    struct uci_context *ctx = NULL;
    struct uci_package *pkg = NULL;
    char section[64];
    int rc = -1;

    if (stage) *stage = "config_write";
    if (!macn || !macn[0]) return -1;
    nc_ipamc_host_section(macn, section, sizeof(section));
    if (!section[0]) return -1;
    if (bak && bak_len && nc_backup_config("dhcp", bak, bak_len) != 0) return -1;
    ctx = uci_alloc_context();
    if (!ctx) return -1;
    if (uci_load(ctx, "dhcp", &pkg) != UCI_OK) goto done;
    if (remove) {
        if (nc_uci_delete_section_pkg(ctx, "dhcp", section) != 0) goto done;
    } else {
        if (nc_uci_ensure_section(ctx, pkg, "dhcp", section, "host") != 0) goto done;
        if (nc_uci_set_pkg(ctx, "dhcp", section, "mac", macn) != 0) goto done;
        if (nc_uci_set_pkg(ctx, "dhcp", section, "ip", ip) != 0) goto done;
        /*
         * An empty name is deleted rather than written as "": dnsmasq treats an
         * empty hostname as a parse error and refuses to start, which would turn
         * a metadata-only edit into a DNS outage.
         */
        if (name && name[0]) {
            if (nc_uci_set_pkg(ctx, "dhcp", section, "name", name) != 0) goto done;
        } else if (nc_uci_delete_pkg(ctx, "dhcp", section, "name") != 0) {
            goto done;
        }
    }
    if (jmx_uci_commit(ctx, "dhcp") != UCI_OK) goto done;
    if (stage) *stage = "runtime_apply";
    if (nc_dnsmasq_restart_wait("/tmp/dw-ipam-reservation-apply.log") != 0) goto done;
    if (stage) *stage = NULL;
    rc = 0;
done:
    if (ctx) uci_free_context(ctx);
    return rc;
}

/*
 * Canonical config readback: read /etc/config/dhcp again through UCI and
 * compare field by field.  A commit that returned UCI_OK is not proof the file
 * holds the value -- this is.
 */
static struct json_object *nc_ipamc_host_readback(const char *macn, const char *ip,
                                                  const char *name, int *ok_out)
{
    struct json_object *rb = json_object_new_object();
    char section[64], got_mac[64] = "", got_ip[64] = "", got_name[128] = "";
    const char *mismatch = NULL;

    nc_ipamc_host_section(macn, section, sizeof(section));
    json_object_object_add(rb, "source", json_object_new_string("/etc/config/dhcp"));
    json_object_object_add(rb, "section", json_object_new_string(section));
    nc_ipamc_uci_get("dhcp", section, "mac", got_mac, sizeof(got_mac));
    nc_ipamc_uci_get("dhcp", section, "ip", got_ip, sizeof(got_ip));
    nc_ipamc_uci_get("dhcp", section, "name", got_name, sizeof(got_name));
    nc_ipamc_add_str_or_null(rb, "mac", got_mac);
    nc_ipamc_add_str_or_null(rb, "ip", got_ip);
    nc_ipamc_add_str_or_null(rb, "name", got_name);
    if (strcasecmp(got_mac, macn ? macn : "")) mismatch = "mac";
    else if (strcmp(got_ip, ip ? ip : "")) mismatch = "ip";
    else if (strcmp(got_name, (name && name[0]) ? name : "")) mismatch = "name";
    json_object_object_add(rb, "matches", json_object_new_boolean(mismatch == NULL));
    json_object_object_add(rb, "mismatch_field",
                           mismatch ? json_object_new_string(mismatch) : NULL);
    if (ok_out) *ok_out = mismatch == NULL;
    return rb;
}

static struct json_object *nc_ipamc_runtime_readback(void)
{
    struct json_object *rt = json_object_new_object();
    int running = nc_dnsmasq_process_running();
    json_object_object_add(rt, "dnsmasq_running", json_object_new_boolean(running));
    json_object_object_add(rt, "listener_ready", json_object_new_boolean(running));
    /*
     * The one thing that genuinely cannot be observed here.  dnsmasq has the
     * reservation, but the client keeps its current address until its next
     * renew, so there is no lease to read back yet.  Reporting available=false
     * with this reason is the difference between an honest response and a page
     * that shows a bound lease that does not exist.
     */
    nc_ipamc_cap_add(rt, "lease_binding", 0,
                     "lease_binding_requires_client_renew", "dhcp_lease_cache");
    return rt;
}

/*
 * Conflict semantics, stated because they are a product decision and not
 * derivable from the schema:
 *
 *   address_conflict - the address is already held in this network by something
 *                      that is not this MAC.  A MAC-less row (gateway, exclude)
 *                      counts: reserving the gateway address is a conflict, not
 *                      a takeover.
 *   mac_conflict     - this MAC already has a reservation in a DIFFERENT
 *                      network.  Same network is deliberately NOT a conflict: it
 *                      is how a client is moved to another address, and the UCI
 *                      section is MAC-keyed so the move replaces in place.
 */
static int nc_ipamc_conflicts(const char *network_id, const char *ip,
                              const char *macn, char *previous_ip,
                              size_t previous_len, const char **code)
{
    sqlite3_stmt *st = NULL;
    int hit = 0;

    if (previous_ip && previous_len) previous_ip[0] = '\0';
    if (nc_prepare(&st, "SELECT source FROM ipam_address WHERE network_id=?1 AND ip=?2 "
                        "AND (mac='' OR mac<>?3) LIMIT 1") != 0) {
        if (code) *code = "storage_error";
        return -1;
    }
    sqlite3_bind_text(st, 1, network_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, ip, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, macn, -1, SQLITE_TRANSIENT);
    hit = sqlite3_step(st) == SQLITE_ROW;
    sqlite3_finalize(st);
    st = NULL;
    if (hit) {
        if (code) *code = "address_conflict";
        return -1;
    }
    if (nc_prepare(&st, "SELECT network_id,ip FROM ipam_address WHERE mac=?1 "
                        "AND source='reservation' AND network_id<>?2 LIMIT 1") != 0) {
        if (code) *code = "storage_error";
        return -1;
    }
    sqlite3_bind_text(st, 1, macn, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, network_id, -1, SQLITE_TRANSIENT);
    hit = sqlite3_step(st) == SQLITE_ROW;
    sqlite3_finalize(st);
    st = NULL;
    if (hit) {
        if (code) *code = "mac_conflict";
        return -1;
    }
    /* Same-network move: recorded so the response can report what it replaced. */
    if (previous_ip && previous_len &&
        nc_prepare(&st, "SELECT ip FROM ipam_address WHERE network_id=?1 AND mac=?2 "
                        "AND source='reservation' AND ip<>?3 LIMIT 1") == 0) {
        sqlite3_bind_text(st, 1, network_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, macn, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 3, ip, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) == SQLITE_ROW && sqlite3_column_text(st, 0))
            snprintf(previous_ip, previous_len, "%s",
                     (const char *)sqlite3_column_text(st, 0));
        sqlite3_finalize(st);
    }
    if (code) *code = NULL;
    return 0;
}

/*
 * Idempotency ledger.  Without it, a client that retries after a dropped
 * response hits expected_version_mismatch -- the first attempt already bumped
 * the revision -- and is told its write conflicted when in fact it succeeded.
 * The stored payload is the inner `data` object, replayed verbatim with a
 * `replayed` marker so the caller can tell a replay from a fresh apply.
 */
static struct json_object *nc_ipamc_ledger_lookup(const char *request_id,
                                                  const char *kind,
                                                  const char *fingerprint,
                                                  int *conflict)
{
    sqlite3_stmt *st = NULL;
    struct json_object *stored = NULL;

    if (conflict) *conflict = 0;
    if (!request_id || !request_id[0]) return NULL;
    if (nc_prepare(&st, "SELECT fingerprint,response_json FROM ipam_write_request "
                        "WHERE request_id=?1 AND kind=?2") != 0)
        return NULL;
    sqlite3_bind_text(st, 1, request_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, kind, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW) {
        const char *fp = (const char *)sqlite3_column_text(st, 0);
        const char *body = (const char *)sqlite3_column_text(st, 1);
        if (fingerprint && fp && strcmp(fp, fingerprint)) {
            if (conflict) *conflict = 1;
        } else if (body && body[0]) {
            stored = json_tokener_parse(body);
        }
    }
    sqlite3_finalize(st);
    return stored;
}

static void nc_ipamc_ledger_store(const char *request_id, const char *kind,
                                  const char *network_id, const char *fingerprint,
                                  struct json_object *data)
{
    sqlite3_stmt *st = NULL;
    const char *body;

    if (!request_id || !request_id[0] || !data) return;
    body = json_object_to_json_string_ext(data, JSON_C_TO_STRING_PLAIN);
    if (!body) return;
    if (nc_prepare(&st, "INSERT INTO ipam_write_request"
                        "(request_id,kind,network_id,fingerprint,response_json,created_at) "
                        "VALUES(?1,?2,?3,?4,?5,?6) ON CONFLICT(request_id) DO UPDATE SET "
                        "kind=excluded.kind,network_id=excluded.network_id,"
                        "fingerprint=excluded.fingerprint,response_json=excluded.response_json") != 0)
        return;
    sqlite3_bind_text(st, 1, request_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, kind, -1, SQLITE_TRANSIENT);
    nc_bind_text_or_null(st, 3, network_id);
    nc_bind_text_or_null(st, 4, fingerprint);
    sqlite3_bind_text(st, 5, body, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 6, nc_now_s());
    nc_step_done(st);
    sqlite3_finalize(st);
}

/*
 * One error shape for the whole write path.  `failure_stage` names where it
 * stopped and the two applied flags say what survived, so a caller can tell
 * "nothing happened" from "config landed but runtime did not" without parsing
 * the error code -- the distinction the handoff calls 假成功.
 */
static struct json_object *nc_ipamc_write_error(const char *code, const char *stage,
                                                sqlite3_int64 revision,
                                                int config_applied,
                                                int runtime_applied,
                                                struct json_object *rollback,
                                                struct json_object *verify)
{
    struct json_object *data = json_object_new_object();
    json_object_object_add(data, "ok", json_object_new_boolean(0));
    json_object_object_add(data, "error", json_object_new_string(code));
    json_object_object_add(data, "failure_stage",
                           stage ? json_object_new_string(stage) : NULL);
    json_object_object_add(data, "revision", json_object_new_int64(revision));
    json_object_object_add(data, "config_applied", json_object_new_boolean(config_applied));
    json_object_object_add(data, "runtime_applied", json_object_new_boolean(runtime_applied));
    json_object_object_add(data, "rollback", rollback);
    json_object_object_add(data, "verify", verify);
    return jmx_gen_api_response_data(API_CODE_ERROR, data);
}


/*
 * Restore /etc/config/dhcp from the backup and put dnsmasq back on it.  The
 * returned object distinguishes "rolled back cleanly" from "rollback itself
 * failed", which is the difference between an error the caller can retry and
 * one that needs a human.
 *
 * nc_copy_file() is used instead of nc_restore_config(): the latter returns void
 * and swallows the copy result, so it cannot tell us whether the restore landed
 * -- and a rollback that silently did nothing is the worst of the three
 * outcomes to report as success.
 */
static struct json_object *nc_ipamc_rollback_uci(const char *bak, int *ok_out,
                                                const char *log)
{
    struct json_object *rb = json_object_new_object();
    int restored = -1, restarted = -1;

    if (bak && bak[0]) restored = nc_copy_file(bak, "/etc/config/dhcp");
    if (restored == 0)
        restarted = nc_dnsmasq_restart_wait(log ? log :
                                            "/tmp/dw-ipam-reservation-rollback.log");
    json_object_object_add(rb, "attempted", json_object_new_boolean(1));
    json_object_object_add(rb, "config_restored", json_object_new_boolean(restored == 0));
    json_object_object_add(rb, "runtime_restored", json_object_new_boolean(restarted == 0));
    json_object_object_add(rb, "ok",
                           json_object_new_boolean(restored == 0 && restarted == 0));
    json_object_object_add(rb, "reason", (restored == 0 && restarted == 0) ? NULL :
                           json_object_new_string(restored != 0 ?
                               "dhcp_config_restore_failed" :
                               "dnsmasq_restart_after_restore_failed"));
    if (ok_out) *ok_out = restored == 0 && restarted == 0;
    return rb;
}

/* A rollback object for the paths that never touched anything. */
static struct json_object *nc_ipamc_rollback_none(const char *reason)
{
    struct json_object *rb = json_object_new_object();
    json_object_object_add(rb, "attempted", json_object_new_boolean(0));
    json_object_object_add(rb, "ok", json_object_new_boolean(1));
    json_object_object_add(rb, "reason",
                           reason ? json_object_new_string(reason) : NULL);
    return rb;
}

/*
 * Removal readback: the section must be gone.  Reusing the upsert readback here
 * would compare against an expected MAC that is precisely what should no longer
 * be on disk, so removal gets its own check.
 */
static struct json_object *nc_ipamc_host_removed_readback(const char *macn,
                                                          int *ok_out)
{
    struct json_object *rb = json_object_new_object();
    char section[64], got_mac[64] = "", got_ip[64] = "";
    int gone;

    nc_ipamc_host_section(macn, section, sizeof(section));
    nc_ipamc_uci_get("dhcp", section, "mac", got_mac, sizeof(got_mac));
    nc_ipamc_uci_get("dhcp", section, "ip", got_ip, sizeof(got_ip));
    gone = !got_mac[0] && !got_ip[0];
    json_object_object_add(rb, "source", json_object_new_string("/etc/config/dhcp"));
    json_object_object_add(rb, "section", json_object_new_string(section));
    json_object_object_add(rb, "removed", json_object_new_boolean(gone));
    json_object_object_add(rb, "matches", json_object_new_boolean(gone));
    json_object_object_add(rb, "mismatch_field", gone ? NULL :
                           json_object_new_string(got_mac[0] ? "mac" : "ip"));
    if (ok_out) *ok_out = gone;
    return rb;
}

/*
 * Everything that touches the config database for one reservation, run inside
 * the caller's transaction so a failure here rolls the whole thing back.
 */
static int nc_ipamc_db_write(const char *network_id, const char *ip,
                             const char *macn, const char *hostname,
                             const char *label, const char *note,
                             const char *previous_ip, int removing,
                             const char **reason)
{
    sqlite3_stmt *st = NULL;
    char expected_id[160];
    int present = 0;

    if (reason) *reason = NULL;
    if (removing) {
        if (nc_prepare(&st, "DELETE FROM ipam_address WHERE network_id=?1 AND mac=?2 "
                            "AND source='reservation'") != 0) goto storage;
        sqlite3_bind_text(st, 1, network_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, macn, -1, SQLITE_TRANSIENT);
        if (nc_step_done(st) != 0) goto addr_failed;
        sqlite3_finalize(st);
        st = NULL;
        /*
         * Scoped to this network on purpose: the same MAC may legitimately hold a
         * reservation in another scope, and this request owns only this one.
         */
        if (nc_prepare(&st, "DELETE FROM dhcp_reservation WHERE mac=?1 AND scope_id IN "
                            "(SELECT id FROM dhcp_scope WHERE lan_id=?2 "
                            "UNION SELECT ?2)") != 0) goto storage;
        sqlite3_bind_text(st, 1, macn, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, network_id, -1, SQLITE_TRANSIENT);
        if (nc_step_done(st) != 0) { if (reason) *reason = "dhcp_reservation_write_failed"; goto fail; }
        sqlite3_finalize(st);
        return 0;
    }
    /*
     * A move leaves the old row behind: the unique key is (network_id,ip,mac), so
     * an upsert at the new address cannot replace the row at the old one, and the
     * table would report the client twice.
     */
    if (previous_ip && previous_ip[0]) {
        if (nc_prepare(&st, "DELETE FROM ipam_address WHERE network_id=?1 AND mac=?2 "
                            "AND ip<>?3 AND source='reservation'") != 0) goto storage;
        sqlite3_bind_text(st, 1, network_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, macn, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 3, ip, -1, SQLITE_TRANSIENT);
        if (nc_step_done(st) != 0) goto addr_failed;
        sqlite3_finalize(st);
        st = NULL;
    }
    snprintf(expected_id, sizeof(expected_id), "%s_%s_%s", network_id, ip, macn);
    if (nc_ipam_upsert_addr_id(expected_id, network_id, ip, macn, hostname, label,
                               "unknown", "reservation", "reserved", note, 0) != 0) {
        if (reason) *reason = "ipam_address_write_failed";
        return -1;
    }
    if (nc_ipam_sync_dhcp_reservation(network_id, ip, macn, label, note) != 0) {
        if (reason) *reason = "dhcp_reservation_write_failed";
        return -1;
    }
    /*
     * Third readback layer, after config and runtime: the row is read back out of
     * the database rather than inferred from a successful step().
     */
    if (nc_prepare(&st, "SELECT 1 FROM ipam_address WHERE id=?1 AND network_id=?2 "
                        "AND ip=?3 AND mac=?4 AND source='reservation'") != 0) goto storage;
    sqlite3_bind_text(st, 1, expected_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, network_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, ip, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 4, macn, -1, SQLITE_TRANSIENT);
    present = sqlite3_step(st) == SQLITE_ROW;
    sqlite3_finalize(st);
    if (!present) {
        if (reason) *reason = "readback_mismatch";
        return -1;
    }
    return 0;
storage:
    if (reason) *reason = "storage_error";
    return -1;
addr_failed:
    if (reason) *reason = "ipam_address_write_failed";
fail:
    if (st) sqlite3_finalize(st);
    return -1;
}

/*
 * Pre-apply rejection: nothing was written, so both applied flags are false and
 * the rollback object says explicitly that there was nothing to roll back.
 */
static struct json_object *nc_ipamc_reject(const char *code, const char *stage,
                                           sqlite3_int64 revision)
{
    return nc_ipamc_write_error(code, stage, revision, 0, 0,
                                nc_ipamc_rollback_none("nothing_applied"), NULL);
}

/*
 * POST /api/v1/bulk-ip/static-reservations/transactions
 *
 * Order of operations, which is the whole design and is not the obvious one:
 *
 *   1. validate, capability gate, conflict check     (no side effects)
 *   2. expected_version check
 *   3. /etc/config/dhcp write + dnsmasq restart      (runtime)
 *   4. config readback, runtime readback
 *   5. BEGIN IMMEDIATE, re-verify revision and conflicts, write rows, verify
 *      them, bump revision, COMMIT                   (config database)
 *   6. same-source jmx_bulk_ip_get() readback
 *
 * Runtime before database, because the database is what step 6 reads: a row for
 * a reservation dnsmasq never received is exactly the 假成功 this handoff
 * forbids.  A failure anywhere before step 5 also leaves `revision` untouched,
 * so the caller's expected_version is still valid and the retry is clean.
 *
 * The conflict check is deliberately NOT held under BEGIN IMMEDIATE across step
 * 3: nc_dnsmasq_restart_wait() has its own multi-second wait, and holding the
 * config-database write lock across it would stall every other writer for the
 * duration.  So the check is optimistic and re-verified inside step 5, where it
 * costs two indexed queries.
 *
 * Error codes are a contract; the full set this returns is
 *   invalid_payload, invalid_action, missing_request_id, request_id_conflict,
 *   network_not_found, invalid_mac, invalid_address, ip_outside_network_subnet,
 *   missing_expected_version, expected_version_mismatch, address_conflict,
 *   mac_conflict, permission_denied, runtime_executor_unavailable, apply_failed,
 *   readback_mismatch, rollback_failed, transaction_busy, storage_error.
 */
struct json_object *jmx_ipam_static_reservation_transaction(struct json_object *req)
{
    struct json_object *data = NULL, *cfg_rb = NULL, *rt_rb = NULL, *stored = NULL;
    struct json_object *envelope = NULL, *snapshot = NULL, *rb = NULL;
    struct json_object *verify = NULL;
    const char *network_id, *mac_in, *ip_in, *hostname, *name, *note, *action;
    const char *request_id, *label, *code = NULL, *stage = NULL, *deny = NULL;
    char macn[32] = "", subnet[64] = "", previous_ip[64] = "", bak[256] = "";
    char fingerprint[512];
    int removing = 0, conflict = 0, ok = 0, rb_ok = 0;
    int64_t expected;
    sqlite3_int64 revision;

    if (!req)
        return nc_ipamc_reject("invalid_payload", "request", 0);
    if (jmx_netconfig_db_init() != 0)
        return nc_ipamc_reject("storage_error", "storage", 0);
    nc_ipam_db_init();
    nc_ipamc_db_init();

    action = nc_json_str_def(req, "action", "set");
    removing = !strcmp(action, "remove") || !strcmp(action, "delete");
    revision = nc_ipam_revision();
    if (!removing && strcmp(action, "set") && strcmp(action, "upsert"))
        return nc_ipamc_reject("invalid_action", "validate", revision);

    network_id = nc_json_str_def(req, "network_id", "");
    mac_in     = nc_json_str_def(req, "mac", "");
    ip_in      = nc_json_str_def(req, "address", nc_json_str_def(req, "ip", ""));
    hostname   = nc_json_str_def(req, "hostname", "");
    name       = nc_json_str_def(req, "name", "");
    note       = nc_json_str_def(req, "note", "");
    request_id = nc_json_str_def(req, "request_id", "");
    label      = name[0] ? name : hostname;
    expected   = nc_json_int64_def(req, "expected_version",
                                   nc_json_int64_def(req, "expected_revision", 0));

    /*
     * request_id is required rather than optional.  It is the only thing that
     * lets a retry after a dropped response be answered with the original result
     * instead of expected_version_mismatch, and making it optional would mean
     * that a client which omits it gets a silently weaker guarantee.
     */
    if (!request_id[0])
        return nc_ipamc_reject("missing_request_id", "validate", revision);
    if (!network_id[0] || !nc_ipam_network_exists(network_id, subnet, sizeof(subnet)))
        return nc_ipamc_reject("network_not_found", "validate", revision);
    if (!nc_mac_normalize(mac_in, macn, sizeof(macn)))
        return nc_ipamc_reject("invalid_mac", "validate", revision);
    if (!removing) {
        if (!nc_ipv4_ok(ip_in))
            return nc_ipamc_reject("invalid_address", "validate", revision);
        if (subnet[0] && !nc_ip_in_cidr_text(ip_in, subnet))
            return nc_ipamc_reject("ip_outside_network_subnet", "validate", revision);
    }
    if (expected < 1)
        return nc_ipamc_reject("missing_expected_version", "validate", revision);

    snprintf(fingerprint, sizeof(fingerprint), "%s|%s|%s|%s|%s|%s",
             removing ? "remove" : "set", network_id, macn,
             removing ? "" : ip_in, label, hostname);

    /*
     * Replay is answered before the capability gate and before the version check,
     * both of which change their answer over time: a request that already
     * succeeded must keep returning its original result even if the box has since
     * become unwritable or the revision has moved on.
     */
    stored = nc_ipamc_ledger_lookup(request_id, "static_reservation", fingerprint,
                                    &conflict);
    if (conflict) {
        json_object_put(stored);
        return nc_ipamc_reject("request_id_conflict", "idempotency", revision);
    }
    if (stored) {
        json_object_object_add(stored, "replayed", json_object_new_boolean(1));
        envelope = jmx_bulk_ip_get();
        if (envelope && json_object_object_get_ex(envelope, "data", &snapshot) && snapshot)
            snapshot = json_object_get(snapshot);
        else
            snapshot = json_object_new_object();
        if (envelope) json_object_put(envelope);
        json_object_object_add(stored, "readback", snapshot);
        return jmx_gen_api_response_data(API_CODE_SUCCESS, stored);
    }

    /*
     * The capability gate is the same probe the read contract publishes, so a
     * client that was told ip_table_static_reservation_write is unavailable gets
     * the matching refusal here instead of a half-applied write.
     */
    if (!nc_ipamc_runtime_writable(&deny))
        return nc_ipamc_reject((deny && !strcmp(deny, "permission_denied")) ?
                               "permission_denied" : "runtime_executor_unavailable",
                               "capability", revision);
    if (expected != revision)
        return nc_ipamc_reject("expected_version_mismatch", "version", revision);
    /*
     * Removal has nothing to conflict with, and running the MAC check for it would
     * refuse to delete a reservation here because the same client also has one in
     * another network.
     */
    if (!removing && nc_ipamc_conflicts(network_id, ip_in, macn, previous_ip,
                                        sizeof(previous_ip), &code) != 0)
        return nc_ipamc_reject(code ? code : "address_conflict", "conflict", revision);

    if (nc_ipamc_host_apply(macn, removing ? "" : ip_in, removing ? "" : label,
                            removing, bak, sizeof(bak), &stage) != 0) {
        rb = nc_ipamc_rollback_uci(bak, &rb_ok, "/tmp/dw-ipam-reservation-rollback.log");
        nc_cleanup_backup(bak);
        /*
         * config_applied stays true when the rollback itself failed: something is
         * on disk that this request put there and could not take back, and
         * reporting that as "nothing applied" would send the caller to the wrong
         * recovery.
         */
        dw_report_config_commit_failed("ipam_reservation", "",
                                       rb_ok ? "apply_failed" : "rollback_failed", rb_ok);
        return nc_ipamc_write_error(rb_ok ? "apply_failed" : "rollback_failed",
                                    stage ? stage : "runtime_apply", revision,
                                    rb_ok ? 0 : 1, 0, rb, NULL);
    }

    cfg_rb = removing ? nc_ipamc_host_removed_readback(macn, &ok)
                      : nc_ipamc_host_readback(macn, ip_in, label, &ok);
    rt_rb = nc_ipamc_runtime_readback();
    verify = json_object_new_object();
    json_object_object_add(verify, "config", cfg_rb);
    json_object_object_add(verify, "runtime", rt_rb);
    if (!ok) { code = "readback_mismatch"; stage = "config_readback"; goto undo; }
    if (!nc_dnsmasq_process_running()) {
        code = "apply_failed";
        stage = "runtime_readback";
        goto undo;
    }

    if (nc_exec("BEGIN IMMEDIATE") != 0) {
        code = "transaction_busy";
        stage = "database";
        goto undo;
    }
    /* Re-verified under the write lock, because steps 1-4 ran unlocked on purpose. */
    if (nc_ipam_revision() != revision) {
        nc_exec("ROLLBACK");
        code = "expected_version_mismatch";
        stage = "database";
        goto undo;
    }
    if (!removing && nc_ipamc_conflicts(network_id, ip_in, macn, previous_ip,
                                        sizeof(previous_ip), &code) != 0) {
        nc_exec("ROLLBACK");
        if (!code) code = "address_conflict";
        stage = "database";
        goto undo;
    }
    if (nc_ipamc_db_write(network_id, ip_in, macn, hostname[0] ? hostname : label,
                          label, note, previous_ip, removing, &code) != 0) {
        nc_exec("ROLLBACK");
        if (!code) code = "storage_error";
        stage = "database";
        goto undo;
    }
    if (nc_exec("UPDATE ipam_meta SET revision=revision+1") != 0) {
        nc_exec("ROLLBACK");
        code = "storage_error";
        stage = "revision";
        goto undo;
    }
    revision = nc_ipam_revision();
    if (nc_exec("COMMIT") != 0) {
        nc_exec("ROLLBACK");
        revision = nc_ipam_revision();      /* the bump did not survive the rollback */
        code = "storage_error";
        stage = "commit";
        goto undo;
    }
    nc_cleanup_backup(bak);

    data = json_object_new_object();
    json_object_object_add(data, "ok", json_object_new_boolean(1));
    json_object_object_add(data, "error", NULL);
    json_object_object_add(data, "failure_stage", NULL);
    json_object_object_add(data, "action",
                           json_object_new_string(removing ? "remove" : "set"));
    json_object_object_add(data, "request_id", json_object_new_string(request_id));
    json_object_object_add(data, "network_id", json_object_new_string(network_id));
    json_object_object_add(data, "mac", json_object_new_string(macn));
    nc_ipamc_add_str_or_null(data, "address", removing ? "" : ip_in);
    nc_ipamc_add_str_or_null(data, "name", label);
    nc_ipamc_add_str_or_null(data, "hostname", hostname);
    /* Non-null only for a move, and then it names the address that was released. */
    nc_ipamc_add_str_or_null(data, "previous_address", previous_ip);
    json_object_object_add(data, "revision", json_object_new_int64(revision));
    json_object_object_add(data, "config_applied", json_object_new_boolean(1));
    json_object_object_add(data, "runtime_applied", json_object_new_boolean(1));
    json_object_object_add(data, "rollback", nc_ipamc_rollback_none("not_needed"));
    json_object_object_add(data, "verify", verify);
    json_object_object_add(data, "replayed", json_object_new_boolean(0));
    /*
     * The ledger stores the decision, not the table: the same-source readback can
     * be large and would be stale on replay anyway, so it is attached after the
     * store and re-read fresh whenever a replay is answered.
     */
    nc_ipamc_ledger_store(request_id, "static_reservation", network_id, fingerprint,
                          data);
    envelope = jmx_bulk_ip_get();
    if (envelope && json_object_object_get_ex(envelope, "data", &snapshot) && snapshot)
        snapshot = json_object_get(snapshot);
    else
        snapshot = json_object_new_object();
    if (envelope) json_object_put(envelope);
    json_object_object_add(data, "readback", snapshot);
    return jmx_gen_api_response_data(API_CODE_SUCCESS, data);

undo:
    /*
     * Compensating rollback.  Reached only after /etc/config/dhcp was written, so
     * there is always something to undo; the database side has already rolled back
     * by itself where it was reached at all.
     */
    rb = nc_ipamc_rollback_uci(bak, &rb_ok, "/tmp/dw-ipam-reservation-rollback.log");
    nc_cleanup_backup(bak);
    dw_report_config_commit_failed("ipam_reservation", "",
                                   rb_ok ? code : "rollback_failed", rb_ok);
    return nc_ipamc_write_error(rb_ok ? code : "rollback_failed", stage, revision,
                                rb_ok ? 0 : 1, 0, rb, verify);
}

/* ------------------------------------------------------------------------- *
 * Import: preview -> commit -> job
 *
 * Three stages because the handoff requires the destructive one to be
 * auditable: preview writes nothing outside its own row, commit refers to a
 * preview by id so it cannot apply something the user never saw, and the job
 * row keeps the per-item results, both readbacks and the rollback outcome after
 * the response has been delivered.
 * ------------------------------------------------------------------------- */

/*
 * One CSV field, RFC4180 subset: double-quoted fields may contain commas,
 * newlines and doubled quotes.  Returns 1 if a field was read.  *eol is set when
 * the field ended the record.
 *
 * Written out rather than done with strtok_r because a quoted hostname
 * containing a comma is not exotic, and strtok_r would split it into two
 * columns and shift every later column by one -- silently importing the wrong
 * address into the wrong network.
 */
static int nc_ipamc_csv_field(const char **pp, char *out, size_t out_len, int *eol)
{
    const char *p = *pp;
    size_t n = 0, i = 0;
    int quoted = 0, was_quoted = 0;

    *eol = 0;
    if (!p || !*p || out_len < 2) return 0;
    if (*p == '"') { quoted = was_quoted = 1; p++; }
    while (*p) {
        if (quoted) {
            if (*p == '"') {
                if (p[1] == '"') { if (n + 1 < out_len) out[n++] = '"'; p += 2; continue; }
                quoted = 0; p++; continue;
            }
        } else {
            if (*p == ',') { p++; break; }
            if (*p == '\n' || *p == '\r') {
                while (*p == '\r') p++;
                if (*p == '\n') p++;
                *eol = 1;
                break;
            }
        }
        if (n + 1 < out_len) out[n++] = *p;
        p++;
    }
    if (!*p) *eol = 1;
    out[n] = '\0';
    /*
     * Hand-edited CSV carries blanks around values and they are not part of them.
     * Quoted fields are left alone: there, a trailing space was asked for.
     */
    if (!was_quoted) {
        while (n > 0 && (out[n - 1] == ' ' || out[n - 1] == '\t')) out[--n] = '\0';
        while (out[i] == ' ' || out[i] == '\t') i++;
        if (i) memmove(out, out + i, n - i + 1);
    }
    *pp = p;
    return 1;
}

/*
 * Header column name -> canonical row key.  Aliases exist so a table exported
 * from the UI can be re-imported without hand-editing the header.
 */
static void nc_ipamc_csv_key(const char *raw, char *out, size_t out_len)
{
    size_t i, n = 0;

    for (i = 0; raw && raw[i] && n + 1 < out_len; i++) {
        char c = raw[i];
        if (c == ' ' || c == '-') c = '_';
        out[n++] = (char)tolower((unsigned char)c);
    }
    out[n] = '\0';
    if (!strcmp(out, "ip") || !strcmp(out, "ip_address"))
        snprintf(out, out_len, "address");
    else if (!strcmp(out, "network"))
        snprintf(out, out_len, "network_id");
    else if (!strcmp(out, "mac_address"))
        snprintf(out, out_len, "mac");
    else if (!strcmp(out, "remark"))
        snprintf(out, out_len, "note");
    else if (!strcmp(out, "device_name") || !strcmp(out, "client_name"))
        snprintf(out, out_len, "name");
}

/*
 * CSV text -> array of row objects carrying `__line` (the physical line the
 * record started on, counted exactly, so a quoted field with an embedded newline
 * does not shift every later line number) and `__extra_columns` (columns past
 * the header, reported rather than dropped).
 */
static struct json_object *nc_ipamc_csv_to_rows(const char *csv, const char **err)
{
    struct json_object *rows = json_object_new_array();
    char cols[16][40], field[256];
    const char *p = csv, *rec;
    int ncols = 0, eol = 0, line = 1;

    if (err) *err = NULL;
    if (!csv || !csv[0]) {
        if (err) *err = "empty_csv";
        json_object_put(rows);
        return NULL;
    }
    /* A UTF-8 BOM from a spreadsheet would otherwise poison the first header cell. */
    if ((unsigned char)p[0] == 0xEF && (unsigned char)p[1] == 0xBB &&
        (unsigned char)p[2] == 0xBF)
        p += 3;
    while (nc_ipamc_csv_field(&p, field, sizeof(field), &eol)) {
        if (ncols < 16) nc_ipamc_csv_key(field, cols[ncols], sizeof(cols[ncols]));
        ncols++;
        if (eol) break;
    }
    if (ncols < 1 || ncols > 16) {
        if (err) *err = ncols > 16 ? "csv_too_many_columns" : "csv_header_missing";
        json_object_put(rows);
        return NULL;
    }
    line++;
    while (*p) {
        struct json_object *row = json_object_new_object();
        int i = 0, any = 0, extra = 0;

        rec = p;
        eol = 0;
        while (i < ncols && nc_ipamc_csv_field(&p, field, sizeof(field), &eol)) {
            if (field[0]) any = 1;
            json_object_object_add(row, cols[i], json_object_new_string(field));
            i++;
            if (eol) break;
        }
        while (!eol && nc_ipamc_csv_field(&p, field, sizeof(field), &eol)) {
            if (field[0]) any = 1;
            extra++;
        }
        json_object_object_add(row, "__line", json_object_new_int(line));
        json_object_object_add(row, "__extra_columns", json_object_new_int(extra));
        while (rec < p) if (*rec++ == '\n') line++;
        if (any) json_object_array_add(rows, row);
        else json_object_put(row);          /* a blank line is not a failed row */
        if (json_object_array_length(rows) > NC_IPAMC_ROWS_MAX) {
            if (err) *err = "too_many_rows";
            json_object_put(rows);
            return NULL;
        }
    }
    return rows;
}

static void nc_ipamc_row_error(struct json_object *list, const char *field,
                               const char *code)
{
    struct json_object *e = json_object_new_object();
    json_object_object_add(e, "field", field ? json_object_new_string(field) : NULL);
    json_object_object_add(e, "code", json_object_new_string(code));
    json_object_array_add(list, e);
}

/* Network lookups are cached: an import of 1000 rows usually names two networks. */
static int nc_ipamc_net_subnet(struct json_object *cache, const char *nid,
                               char *out, size_t out_len)
{
    struct json_object *hit = NULL, *okj = NULL, *sn = NULL, *entry;
    char subnet[64] = "";
    int ok;

    if (out && out_len) out[0] = '\0';
    if (!nid || !nid[0]) return 0;
    if (json_object_object_get_ex(cache, nid, &hit) && hit) {
        json_object_object_get_ex(hit, "ok", &okj);
        json_object_object_get_ex(hit, "subnet", &sn);
        if (sn && out && out_len) snprintf(out, out_len, "%s", json_object_get_string(sn));
        return okj ? json_object_get_boolean(okj) : 0;
    }
    ok = nc_ipam_network_exists(nid, subnet, sizeof(subnet)) ? 1 : 0;
    entry = json_object_new_object();
    json_object_object_add(entry, "ok", json_object_new_boolean(ok));
    json_object_object_add(entry, "subnet", json_object_new_string(subnet));
    json_object_object_add(cache, nid, entry);
    if (out && out_len) snprintf(out, out_len, "%s", subnet);
    return ok;
}

static int nc_ipamc_existing_reservation_ip(const char *nid, const char *macn,
                                            char *out, size_t out_len)
{
    sqlite3_stmt *st = NULL;
    int found = 0;

    if (out && out_len) out[0] = '\0';
    if (nc_prepare(&st, "SELECT ip FROM ipam_address WHERE network_id=?1 AND mac=?2 "
                        "AND source='reservation' LIMIT 1") != 0)
        return 0;
    sqlite3_bind_text(st, 1, nid, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, macn, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW && sqlite3_column_text(st, 0)) {
        found = 1;
        if (out && out_len)
            snprintf(out, out_len, "%s", (const char *)sqlite3_column_text(st, 0));
    }
    sqlite3_finalize(st);
    return found;
}

/* The keys an import row may carry.  Anything else is reported, never ignored. */
static int nc_ipamc_known_row_key(const char *k)
{
    static const char *known[] = { "network_id", "mac", "address", "hostname",
                                   "name", "note", "expires_at", NULL };
    int i;
    if (!k) return 0;
    if (!strcmp(k, "__line") || !strcmp(k, "__extra_columns")) return 1;
    for (i = 0; known[i]; i++) if (!strcmp(k, known[i])) return 1;
    return 0;
}

/*
 * Validate one row against the request, against the rest of the batch and
 * against the current database.  Every rejection is a stable code attached to
 * the field that caused it: a preview that says only "invalid" cannot be acted
 * on, and the handoff asks for field-level errors with line numbers.
 */
static struct json_object *nc_ipamc_validate_row(struct json_object *row,
                                                 struct json_object *netcache,
                                                 struct json_object *seen_mac,
                                                 struct json_object *seen_addr,
                                                 const char *default_network,
                                                 int strict_unknown)
{
    struct json_object *item = json_object_new_object();
    struct json_object *errors = json_object_new_array();
    struct json_object *warnings = json_object_new_array();
    const char *nid, *mac_in, *ip_in, *hostname, *name, *note, *expires;
    const char *code = NULL, *action = NULL;
    char macn[32] = "", subnet[64] = "", prev[64] = "", existing[64] = "", key[192];
    int line, extra, net_ok = 0, ok_so_far;

    line = nc_json_int_def(row, "__line", 0);
    extra = nc_json_int_def(row, "__extra_columns", 0);
    nid = nc_json_str_def(row, "network_id", "");
    if (!nid[0] && default_network) nid = default_network;
    mac_in   = nc_json_str_def(row, "mac", "");
    ip_in    = nc_json_str_def(row, "address", nc_json_str_def(row, "ip", ""));
    hostname = nc_json_str_def(row, "hostname", "");
    name     = nc_json_str_def(row, "name", "");
    note     = nc_json_str_def(row, "note", "");
    expires  = nc_json_str_def(row, "expires_at", "");

    /*
     * Unknown keys are warnings by default so a newer exporter does not break the
     * import, and errors when the caller asks for strict mode.  Either way they
     * appear in the response -- dropping them silently is how an import quietly
     * loses half of what the user submitted.
     */
    json_object_object_foreach(row, rk, rv) {
        (void)rv;
        if (!nc_ipamc_known_row_key(rk) && strcmp(rk, "ip"))
            nc_ipamc_row_error(strict_unknown ? errors : warnings, rk, "unknown_field");
    }
    if (extra > 0)
        nc_ipamc_row_error(strict_unknown ? errors : warnings, "__extra_columns",
                           "unknown_field");

    if (!nid[0])
        nc_ipamc_row_error(errors, "network_id", "network_not_found");
    else if (!(net_ok = nc_ipamc_net_subnet(netcache, nid, subnet, sizeof(subnet))))
        nc_ipamc_row_error(errors, "network_id", "network_not_found");
    if (!mac_in[0])
        nc_ipamc_row_error(errors, "mac", "invalid_mac");
    else if (!nc_mac_normalize(mac_in, macn, sizeof(macn)))
        nc_ipamc_row_error(errors, "mac", "invalid_mac");
    if (!ip_in[0])
        nc_ipamc_row_error(errors, "address", "invalid_address");
    else if (!nc_ipv4_ok(ip_in))
        nc_ipamc_row_error(errors, "address", "invalid_address");
    else if (net_ok && subnet[0] && !nc_ip_in_cidr_text(ip_in, subnet))
        nc_ipamc_row_error(errors, "address", "ip_outside_network_subnet");
    /*
     * A static reservation has no expiry here: dnsmasq holds the host entry until
     * it is removed.  A row that asks for one is rejected rather than imported
     * with the field quietly dropped, which would look like an accepted lease
     * time that nothing honours.
     */
    if (expires[0])
        nc_ipamc_row_error(errors, "expires_at",
                           (strtoll(expires, NULL, 10) > 0 || strchr(expires, 'T')) ?
                           "expires_at_not_supported" : "invalid_expires_at");

    ok_so_far = json_object_array_length(errors) == 0;
    if (ok_so_far) {
        snprintf(key, sizeof(key), "%s|%s", nid, macn);
        if (json_object_object_get_ex(seen_mac, key, NULL)) {
            nc_ipamc_row_error(errors, "mac", "duplicate_mac_in_batch");
            ok_so_far = 0;
        } else {
            json_object_object_add(seen_mac, key, json_object_new_int(line));
        }
        snprintf(key, sizeof(key), "%s|%s", nid, ip_in);
        if (json_object_object_get_ex(seen_addr, key, NULL)) {
            nc_ipamc_row_error(errors, "address", "duplicate_address_in_batch");
            ok_so_far = 0;
        } else {
            json_object_object_add(seen_addr, key, json_object_new_int(line));
        }
    }
    if (ok_so_far &&
        nc_ipamc_conflicts(nid, ip_in, macn, prev, sizeof(prev), &code) != 0) {
        nc_ipamc_row_error(errors, !code || strcmp(code, "mac_conflict") ?
                           "address" : "mac", code ? code : "address_conflict");
        ok_so_far = 0;
    }
    if (ok_so_far) {
        if (!nc_ipamc_existing_reservation_ip(nid, macn, existing, sizeof(existing)))
            action = "create";
        else if (!strcmp(existing, ip_in))
            action = "reapply";        /* in the database already, but /etc/config may not have it */
        else
            action = "update";
    }

    json_object_object_add(item, "line", json_object_new_int(line));
    nc_ipamc_add_str_or_null(item, "network_id", nid);
    nc_ipamc_add_str_or_null(item, "mac", macn[0] ? macn : mac_in);
    nc_ipamc_add_str_or_null(item, "address", ip_in);
    nc_ipamc_add_str_or_null(item, "name", name[0] ? name : hostname);
    nc_ipamc_add_str_or_null(item, "hostname", hostname);
    nc_ipamc_add_str_or_null(item, "note", note);
    nc_ipamc_add_str_or_null(item, "previous_address", prev[0] ? prev : existing);
    json_object_object_add(item, "action",
                           action ? json_object_new_string(action) : NULL);
    json_object_object_add(item, "valid", json_object_new_boolean(ok_so_far));
    json_object_object_add(item, "errors", errors);
    json_object_object_add(item, "warnings", warnings);
    return item;
}

/*
 * A unique id for a preview or a job row.  /dev/urandom first: the legacy import
 * table keys its jobs "job-<epoch>", which collides for two imports inside the
 * same second and then loses one of them to the PRIMARY KEY.
 */
static void nc_ipamc_new_id(const char *prefix, char *out, size_t out_len)
{
    static unsigned long seq;
    unsigned char rnd[8];
    char hex[17];
    FILE *fp;
    size_t got = 0, i;

    if (!out || !out_len) return;
    fp = fopen("/dev/urandom", "rb");
    if (fp) {
        got = fread(rnd, 1, sizeof(rnd), fp);
        fclose(fp);
    }
    if (got == sizeof(rnd)) {
        for (i = 0; i < sizeof(rnd); i++) snprintf(hex + i * 2, 3, "%02x", rnd[i]);
        hex[16] = '\0';
        snprintf(out, out_len, "%s-%s", prefix ? prefix : "id", hex);
        return;
    }
    snprintf(out, out_len, "%s-%lld-%d-%lu", prefix ? prefix : "id",
             (long long)nc_now_s(), (int)getpid(), ++seq);
}

/*
 * The rows to preview, from either `rows` (already structured) or `csv`.  Every
 * row carries __line so each error can name the line the user sees in their
 * file; a request-supplied array is numbered from 1 the same way.
 */
static struct json_object *nc_ipamc_rows_from_request(struct json_object *req,
                                                      const char **err)
{
    struct json_object *rows = NULL, *out, *src;
    const char *csv;
    size_t i, n;

    if (err) *err = NULL;
    if (json_object_object_get_ex(req, "rows", &rows) && rows &&
        json_object_is_type(rows, json_type_array)) {
        n = json_object_array_length(rows);
        if (n == 0) { if (err) *err = "empty_rows"; return NULL; }
        if (n > NC_IPAMC_ROWS_MAX) { if (err) *err = "too_many_rows"; return NULL; }
        out = json_object_new_array();
        for (i = 0; i < n; i++) {
            struct json_object *row = json_object_new_object();
            src = json_object_array_get_idx(rows, i);
            if (src && json_object_is_type(src, json_type_object)) {
                json_object_object_foreach(src, rk, rv)
                    nc_ipamc_add_shared(row, rk, rv);
            }
            if (!json_object_object_get_ex(row, "__line", NULL))
                json_object_object_add(row, "__line", json_object_new_int((int)i + 1));
            json_object_array_add(out, row);
        }
        return out;
    }
    csv = nc_json_str_def(req, "csv", "");
    if (!csv[0]) { if (err) *err = "missing_rows"; return NULL; }
    if (strlen(csv) > NC_IPAMC_CSV_MAX) { if (err) *err = "csv_too_large"; return NULL; }
    return nc_ipamc_csv_to_rows(csv, err);
}

/*
 * The confirmation digest a commit has to echo.  Made of the counts the user was
 * shown rather than a hash of the payload, for two reasons: it changes whenever
 * the effect of the import changes, and a client that only kept the summary can
 * still reproduce it.
 */
static void nc_ipamc_confirm_digest(int rows_valid, int creates, int updates,
                                    int reapplies, sqlite3_int64 revision,
                                    char *out, size_t out_len)
{
    snprintf(out, out_len, "v1|%d|%d|%d|%d|%lld", rows_valid, creates, updates,
             reapplies, (long long)revision);
}

/*
 * Validate every row and build the preview.  `items` is what the user reviews,
 * `plan` is the subset a commit will execute -- kept separate so commit never has
 * to re-decide which rows were acceptable, and so a row that failed validation
 * cannot reach the apply path at all.
 *
 * Nothing here writes DHCP, UCI or runtime state.
 */
static struct json_object *nc_ipamc_preview_build(struct json_object *rows,
                                                  const char *default_network,
                                                  int strict_unknown,
                                                  sqlite3_int64 revision,
                                                  struct json_object **plan_out,
                                                  struct json_object **summary_out)
{
    struct json_object *items = json_object_new_array();
    struct json_object *plan = json_object_new_array();
    struct json_object *summary = json_object_new_object();
    struct json_object *netcache = json_object_new_object();
    struct json_object *seen_mac = json_object_new_object();
    struct json_object *seen_addr = json_object_new_object();
    struct json_object *netset = json_object_new_object();
    struct json_object *netlist = json_object_new_array();
    int total, i, valid = 0, creates = 0, updates = 0, reapplies = 0, warned = 0;
    char digest[128];

    total = rows ? (int)json_object_array_length(rows) : 0;
    for (i = 0; i < total; i++) {
        struct json_object *item, *warnings = NULL;
        const char *act;

        item = nc_ipamc_validate_row(json_object_array_get_idx(rows, i), netcache,
                                     seen_mac, seen_addr, default_network,
                                     strict_unknown);
        if (json_object_object_get_ex(item, "warnings", &warnings) && warnings &&
            json_object_array_length(warnings) > 0)
            warned++;
        if (nc_json_bool_def(item, "valid", 0)) {
            valid++;
            act = nc_json_str_def(item, "action", "");
            if (!strcmp(act, "create")) creates++;
            else if (!strcmp(act, "update")) updates++;
            else reapplies++;
            json_object_object_add(netset, nc_json_str_def(item, "network_id", ""),
                                   json_object_new_boolean(1));
            json_object_array_add(plan, json_object_get(item));
        }
        json_object_array_add(items, item);
    }
    json_object_object_foreach(netset, nk, nv) {
        (void)nv;
        json_object_array_add(netlist, json_object_new_string(nk));
    }
    nc_ipamc_confirm_digest(valid, creates, updates, reapplies, revision,
                            digest, sizeof(digest));

    json_object_object_add(summary, "rows_total", json_object_new_int(total));
    json_object_object_add(summary, "rows_valid", json_object_new_int(valid));
    json_object_object_add(summary, "rows_invalid", json_object_new_int(total - valid));
    json_object_object_add(summary, "rows_with_warnings", json_object_new_int(warned));
    json_object_object_add(summary, "creates", json_object_new_int(creates));
    json_object_object_add(summary, "updates", json_object_new_int(updates));
    json_object_object_add(summary, "reapplies", json_object_new_int(reapplies));
    json_object_object_add(summary, "removes", json_object_new_int(0));
    json_object_object_add(summary, "networks", netlist);
    json_object_object_add(summary, "revision", json_object_new_int64(revision));
    json_object_object_add(summary, "confirm_digest", json_object_new_string(digest));

    json_object_put(netcache);
    json_object_put(seen_mac);
    json_object_put(seen_addr);
    json_object_put(netset);
    if (plan_out) *plan_out = plan; else json_object_put(plan);
    if (summary_out) *summary_out = summary; else json_object_put(summary);
    return items;
}

/* Drop previews nobody committed.  Cheap, and it keeps a table that only ever
 * grows from becoming the reason an import fails months later. */
static void nc_ipamc_preview_expire(int64_t now)
{
    sqlite3_stmt *st = NULL;
    if (nc_prepare(&st, "DELETE FROM ipam_import_preview WHERE expires_at<?1") != 0)
        return;
    sqlite3_bind_int64(st, 1, now);
    nc_step_done(st);
    sqlite3_finalize(st);
}

/*
 * POST /api/v1/bulk-ip/import/preview
 *
 * Validates and reports; it does not touch /etc/config/dhcp, dnsmasq or any
 * ipam_address row.  It does persist one row in ipam_import_preview, so the
 * response says `side_effects.preview_row: true` instead of claiming to be
 * side-effect free -- commit has to be able to refer to exactly what the user
 * approved, and that means the plan has to be stored somewhere.
 *
 * Error codes: invalid_payload, storage_error, missing_rows, empty_rows,
 * empty_csv, too_many_rows, csv_too_large, csv_header_missing,
 * csv_too_many_columns.
 */
struct json_object *jmx_ipam_import_preview(struct json_object *req)
{
    struct json_object *data, *rows = NULL, *items = NULL, *plan = NULL;
    struct json_object *summary = NULL, *confirm, *effects;
    sqlite3_stmt *st = NULL;
    const char *err = NULL, *default_network;
    char preview_id[80], iso_created[32], iso_expires[32];
    int strict, stored_ok = 0, valid;
    int64_t now, expires;
    sqlite3_int64 revision;

    if (!req)
        return nc_ipamc_reject("invalid_payload", "request", 0);
    if (jmx_netconfig_db_init() != 0)
        return nc_ipamc_reject("storage_error", "storage", 0);
    nc_ipam_db_init();
    nc_ipamc_db_init();
    revision = nc_ipam_revision();

    default_network = nc_json_str_def(req, "network_id", "");
    strict = nc_json_bool_def(req, "strict_unknown_fields", 0);
    rows = nc_ipamc_rows_from_request(req, &err);
    if (!rows)
        return nc_ipamc_reject(err ? err : "invalid_payload", "parse", revision);

    items = nc_ipamc_preview_build(rows, default_network[0] ? default_network : NULL,
                                   strict, revision, &plan, &summary);
    json_object_put(rows);
    valid = nc_json_int_def(summary, "rows_valid", 0);

    now = nc_now_s();
    expires = now + NC_IPAMC_PREVIEW_TTL_S;
    nc_ipamc_preview_expire(now);
    nc_ipamc_new_id("prev", preview_id, sizeof(preview_id));
    if (nc_prepare(&st, "INSERT INTO ipam_import_preview"
                        "(id,network_id,revision,rows_total,rows_valid,rows_invalid,"
                        "payload_json,summary_json,created_at,expires_at) "
                        "VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)") == 0) {
        sqlite3_bind_text(st, 1, preview_id, -1, SQLITE_TRANSIENT);
        nc_bind_text_or_null(st, 2, default_network);
        sqlite3_bind_int64(st, 3, revision);
        sqlite3_bind_int(st, 4, nc_json_int_def(summary, "rows_total", 0));
        sqlite3_bind_int(st, 5, valid);
        sqlite3_bind_int(st, 6, nc_json_int_def(summary, "rows_invalid", 0));
        sqlite3_bind_text(st, 7, json_object_to_json_string_ext(plan,
                          JSON_C_TO_STRING_PLAIN), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 8, json_object_to_json_string_ext(summary,
                          JSON_C_TO_STRING_PLAIN), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 9, now);
        sqlite3_bind_int64(st, 10, expires);
        stored_ok = nc_step_done(st) == 0;
        sqlite3_finalize(st);
    }
    json_object_put(plan);
    if (!stored_ok) {
        json_object_put(items);
        json_object_put(summary);
        return nc_ipamc_reject("storage_error", "preview_store", revision);
    }

    nc_ipamc_iso8601(now, iso_created, sizeof(iso_created));
    nc_ipamc_iso8601(expires, iso_expires, sizeof(iso_expires));
    confirm = json_object_new_object();
    json_object_object_add(confirm, "digest",
                           json_object_new_string(nc_json_str_def(summary,
                                                  "confirm_digest", "")));
    json_object_object_add(confirm, "rows_valid", json_object_new_int(valid));
    json_object_object_add(confirm, "creates",
                           json_object_new_int(nc_json_int_def(summary, "creates", 0)));
    json_object_object_add(confirm, "updates",
                           json_object_new_int(nc_json_int_def(summary, "updates", 0)));
    json_object_object_add(confirm, "reapplies",
                           json_object_new_int(nc_json_int_def(summary, "reapplies", 0)));
    /*
     * What this call did and did not do, spelled out rather than implied.  The
     * frontend gates its confirm dialog on these, and "preview wrote nothing" was
     * not true enough to publish.
     */
    effects = json_object_new_object();
    json_object_object_add(effects, "dhcp_config", json_object_new_boolean(0));
    json_object_object_add(effects, "runtime", json_object_new_boolean(0));
    json_object_object_add(effects, "ipam_address", json_object_new_boolean(0));
    json_object_object_add(effects, "preview_row", json_object_new_boolean(1));

    data = json_object_new_object();
    json_object_object_add(data, "ok", json_object_new_boolean(1));
    json_object_object_add(data, "error", NULL);
    json_object_object_add(data, "failure_stage", NULL);
    json_object_object_add(data, "preview_id", json_object_new_string(preview_id));
    json_object_object_add(data, "created_at", json_object_new_string(iso_created));
    json_object_object_add(data, "expires_at", json_object_new_string(iso_expires));
    json_object_object_add(data, "expires_in_s",
                           json_object_new_int(NC_IPAMC_PREVIEW_TTL_S));
    json_object_object_add(data, "revision", json_object_new_int64(revision));
    nc_ipamc_add_str_or_null(data, "network_id", default_network);
    json_object_object_add(data, "strict_unknown_fields",
                           json_object_new_boolean(strict != 0));
    json_object_object_add(data, "rows_total",
                           json_object_new_int(nc_json_int_def(summary, "rows_total", 0)));
    json_object_object_add(data, "rows_valid", json_object_new_int(valid));
    json_object_object_add(data, "rows_invalid",
                           json_object_new_int(nc_json_int_def(summary, "rows_invalid", 0)));
    /*
     * A preview with no acceptable row is still a successful preview -- it is the
     * report the user asked for.  commit_allowed is what the button binds to.
     */
    json_object_object_add(data, "commit_allowed", json_object_new_boolean(valid > 0));
    json_object_object_add(data, "confirmation", confirm);
    json_object_object_add(data, "summary", summary);
    json_object_object_add(data, "items", items);
    json_object_object_add(data, "side_effects", effects);
    return jmx_gen_api_response_data(API_CODE_SUCCESS, data);
}

/*
 * Project the whole plan into /etc/config/dhcp: one backup, one uci context, one
 * commit, one dnsmasq restart.  Applying row by row would restart dnsmasq N times
 * and, on the first failure, leave the rows before it on disk -- exactly the
 * 半套配置 the handoff forbids.  Here a failure at any point means one restore of
 * one backup puts the whole file back.
 */
static int nc_ipamc_batch_apply(struct json_object *plan, char *bak, size_t bak_len,
                                const char **stage, int *failed_line,
                                const char **failed_reason)
{
    struct uci_context *ctx = NULL;
    struct uci_package *pkg = NULL;
    char section[64];
    int i, n, rc = -1;

    if (stage) *stage = "config_write";
    if (failed_line) *failed_line = 0;
    if (failed_reason) *failed_reason = NULL;
    n = plan ? (int)json_object_array_length(plan) : 0;
    if (n <= 0) {
        if (failed_reason) *failed_reason = "empty_plan";
        return -1;
    }
    if (bak && bak_len && nc_backup_config("dhcp", bak, bak_len) != 0) {
        if (failed_reason) *failed_reason = "backup_failed";
        return -1;
    }
    ctx = uci_alloc_context();
    if (!ctx) {
        if (failed_reason) *failed_reason = "uci_context_failed";
        return -1;
    }
    if (uci_load(ctx, "dhcp", &pkg) != UCI_OK) {
        if (failed_reason) *failed_reason = "uci_load_failed";
        goto done;
    }
    for (i = 0; i < n; i++) {
        struct json_object *row = json_object_array_get_idx(plan, i);
        const char *macn = nc_json_str_def(row, "mac", "");
        const char *ip = nc_json_str_def(row, "address", "");
        const char *name = nc_json_str_def(row, "name", "");
        const char *why = NULL;

        nc_ipamc_host_section(macn, section, sizeof(section));
        if (!macn[0] || !section[0] || !ip[0])
            why = "invalid_row";
        else if (nc_uci_ensure_section(ctx, pkg, "dhcp", section, "host") != 0 ||
                 nc_uci_set_pkg(ctx, "dhcp", section, "mac", macn) != 0 ||
                 nc_uci_set_pkg(ctx, "dhcp", section, "ip", ip) != 0)
            why = "config_write_failed";
        /* Empty name is deleted, not written: dnsmasq refuses to start on an
         * empty hostname, so writing "" would turn an import into a DNS outage. */
        else if (name[0] ? nc_uci_set_pkg(ctx, "dhcp", section, "name", name) != 0
                         : nc_uci_delete_pkg(ctx, "dhcp", section, "name") != 0)
            why = "config_write_failed";
        if (why) {
            if (failed_line) *failed_line = nc_json_int_def(row, "line", i + 1);
            if (failed_reason) *failed_reason = why;
            goto done;
        }
    }
    if (jmx_uci_commit(ctx, "dhcp") != UCI_OK) {
        if (failed_reason) *failed_reason = "uci_commit_failed";
        goto done;
    }
    if (stage) *stage = "runtime_apply";
    if (nc_dnsmasq_restart_wait("/tmp/dw-ipam-import-apply.log") != 0) {
        if (failed_reason) *failed_reason = "dnsmasq_restart_failed";
        goto done;
    }
    if (stage) *stage = NULL;
    rc = 0;
done:
    if (ctx) uci_free_context(ctx);
    return rc;
}

/* Load a stored preview.  Returns 0 on success, -1 when the id is unknown and 1
 * when the row exists but has expired -- three different answers because the
 * caller has to tell "wrong id" from "took too long to confirm". */
static int nc_ipamc_preview_load(const char *preview_id, int64_t now,
                                 struct json_object **plan,
                                 struct json_object **summary,
                                 sqlite3_int64 *revision)
{
    sqlite3_stmt *st = NULL;
    int rc = -1;

    if (plan) *plan = NULL;
    if (summary) *summary = NULL;
    if (revision) *revision = 0;
    if (!preview_id || !preview_id[0]) return -1;
    if (nc_prepare(&st, "SELECT payload_json,summary_json,revision,expires_at "
                        "FROM ipam_import_preview WHERE id=?1") != 0)
        return -1;
    sqlite3_bind_text(st, 1, preview_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW) {
        const char *pj = (const char *)sqlite3_column_text(st, 0);
        const char *sj = (const char *)sqlite3_column_text(st, 1);
        int64_t exp = sqlite3_column_int64(st, 3);
        if (revision) *revision = sqlite3_column_int64(st, 2);
        if (exp > 0 && exp < now) {
            rc = 1;
        } else {
            if (plan) *plan = (pj && pj[0]) ? json_tokener_parse(pj) : NULL;
            if (summary) *summary = (sj && sj[0]) ? json_tokener_parse(sj) : NULL;
            rc = (plan && *plan) ? 0 : -1;
        }
    }
    sqlite3_finalize(st);
    return rc;
}

/* A preview is single-use.  Deleting it on success is what stops a second commit
 * with a fresh request_id from re-applying rows the user confirmed once: that
 * second call gets `preview_not_found`, which is the truthful answer, instead of
 * quietly writing the same batch again. */
static void nc_ipamc_preview_consume(const char *preview_id)
{
    sqlite3_stmt *st = NULL;

    if (!preview_id || !preview_id[0]) return;
    if (nc_prepare(&st, "DELETE FROM ipam_import_preview WHERE id=?1") != 0) return;
    sqlite3_bind_text(st, 1, preview_id, -1, SQLITE_TRANSIENT);
    nc_step_done(st);
    sqlite3_finalize(st);
}

/* One row per commit attempt, written before the apply starts and updated when it
 * finishes, so a crash mid-apply leaves a job that says `running` rather than
 * nothing at all. */
static void nc_ipamc_job_store(const char *job_id, const char *preview_id,
                               const char *request_id, const char *network_id,
                               const char *status, const char *error,
                               struct json_object *results,
                               sqlite3_int64 rev_before, sqlite3_int64 rev_after)
{
    sqlite3_stmt *st = NULL;

    if (!job_id || !job_id[0]) return;
    if (nc_prepare(&st, "INSERT INTO ipam_import_job_state"
                        "(job_id,preview_id,request_id,network_id,status,error,"
                        "results_json,revision_before,revision_after,created_at,updated_at) "
                        "VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?10) "
                        "ON CONFLICT(job_id) DO UPDATE SET status=excluded.status,"
                        "error=excluded.error,results_json=excluded.results_json,"
                        "revision_after=excluded.revision_after,"
                        "updated_at=excluded.updated_at") != 0)
        return;
    sqlite3_bind_text(st, 1, job_id, -1, SQLITE_TRANSIENT);
    nc_bind_text_or_null(st, 2, preview_id);
    nc_bind_text_or_null(st, 3, request_id);
    nc_bind_text_or_null(st, 4, network_id);
    sqlite3_bind_text(st, 5, status ? status : "running", -1, SQLITE_TRANSIENT);
    nc_bind_text_or_null(st, 6, error);
    if (results)
        sqlite3_bind_text(st, 7, json_object_to_json_string_ext(results,
                          JSON_C_TO_STRING_PLAIN), -1, SQLITE_TRANSIENT);
    else
        sqlite3_bind_null(st, 7);
    sqlite3_bind_int64(st, 8, rev_before);
    sqlite3_bind_int64(st, 9, rev_after);
    sqlite3_bind_int64(st, 10, nc_now_s());
    nc_step_done(st);
    sqlite3_finalize(st);
}

/* A column that may be SQL NULL becomes JSON null, not "".  An empty error string
 * and "no error" are different answers and the job status reader must not blur
 * them. */
static void nc_ipamc_add_col_or_null(struct json_object *o, const char *key,
                                     sqlite3_stmt *st, int col)
{
    const char *v = (const char *)sqlite3_column_text(st, col);
    json_object_object_add(o, key, (v && v[0]) ? json_object_new_string(v) : NULL);
}

static struct json_object *nc_ipamc_job_json(const char *job_id)
{
    sqlite3_stmt *st = NULL;
    struct json_object *job = NULL;

    if (!job_id || !job_id[0]) return NULL;
    if (nc_prepare(&st, "SELECT preview_id,request_id,network_id,status,error,"
                        "results_json,revision_before,revision_after,created_at,"
                        "updated_at FROM ipam_import_job_state WHERE job_id=?1") != 0)
        return NULL;
    sqlite3_bind_text(st, 1, job_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW) {
        const char *rj = (const char *)sqlite3_column_text(st, 5);
        struct json_object *results = (rj && rj[0]) ? json_tokener_parse(rj) : NULL;
        char iso_created[32], iso_updated[32];

        nc_ipamc_iso8601(sqlite3_column_int64(st, 8), iso_created, sizeof(iso_created));
        nc_ipamc_iso8601(sqlite3_column_int64(st, 9), iso_updated, sizeof(iso_updated));
        job = json_object_new_object();
        json_object_object_add(job, "job_id", json_object_new_string(job_id));
        nc_ipamc_add_col_or_null(job, "preview_id", st, 0);
        nc_ipamc_add_col_or_null(job, "request_id", st, 1);
        nc_ipamc_add_col_or_null(job, "network_id", st, 2);
        nc_ipamc_add_col_or_null(job, "status", st, 3);
        nc_ipamc_add_col_or_null(job, "error", st, 4);
        json_object_object_add(job, "revision_before",
                               json_object_new_int64(sqlite3_column_int64(st, 6)));
        json_object_object_add(job, "revision_after",
                               json_object_new_int64(sqlite3_column_int64(st, 7)));
        nc_ipamc_add_str_or_null(job, "created_at", iso_created);
        nc_ipamc_add_str_or_null(job, "updated_at", iso_updated);
        json_object_object_add(job, "results",
                               results ? results : json_object_new_array());
        json_object_object_add(job, "legacy", json_object_new_boolean(0));
    }
    sqlite3_finalize(st);
    return job;
}

/* One per-row outcome.  `status` is the row's own fate, which is not always the
 * job's: a batch that rolled back has rows that were never applied and rows that
 * were applied and taken back, and the difference matters when the user retries. */
static struct json_object *nc_ipamc_result_row(struct json_object *row,
                                               const char *status, const char *code,
                                               struct json_object *readback)
{
    struct json_object *r = json_object_new_object();
    json_object_object_add(r, "line", json_object_new_int(nc_json_int_def(row, "line", 0)));
    nc_ipamc_add_str_or_null(r, "network_id", nc_json_str_def(row, "network_id", ""));
    nc_ipamc_add_str_or_null(r, "mac", nc_json_str_def(row, "mac", ""));
    nc_ipamc_add_str_or_null(r, "address", nc_json_str_def(row, "address", ""));
    nc_ipamc_add_str_or_null(r, "name", nc_json_str_def(row, "name", ""));
    nc_ipamc_add_str_or_null(r, "action", nc_json_str_def(row, "action", ""));
    json_object_object_add(r, "status", json_object_new_string(status ? status : "unknown"));
    nc_ipamc_add_str_or_null(r, "code", code);
    json_object_object_add(r, "config_readback", readback);
    return r;
}

/* Add a key to the data object inside an already-built response envelope. */
static struct json_object *nc_ipamc_env_add(struct json_object *env, const char *key,
                                            struct json_object *value)
{
    struct json_object *d = NULL;
    if (env && json_object_object_get_ex(env, "data", &d) && d)
        json_object_object_add(d, key, value);
    else
        json_object_put(value);
    return env;
}

/*
 * POST /api/v1/bulk-ip/import/commit
 *
 * Executes a stored preview.  Same ordering as the single-reservation write --
 * /etc/config/dhcp and dnsmasq first, config database second, same-source
 * readback last -- and the same reason: the database is what the readback reads,
 * so a row written for a reservation dnsmasq never received would be a 假成功.
 *
 * Batch atomicity is one backup, one uci context, one commit, one dnsmasq
 * restart, then one database transaction.  Any failure restores that single
 * backup and restarts dnsmasq once, so the file can never be left holding half
 * of the import.
 *
 * Three things worth knowing before reading the code:
 *
 *  - `queued` is never returned.  Commit runs inline, so the job goes straight to
 *    `running` and then to `succeeded` / `failed` / `rolled_back`.  Reporting a
 *    queue that does not exist would be the same lie as reporting an apply that
 *    did not happen.
 *  - The preview must have been computed against the current revision.  If the
 *    table moved in between, its conflict verdicts and its digest describe a
 *    state that is gone: that is `preview_stale`, not a silent re-validation.
 *  - Rows are applied in file order and each row's conflict check runs after the
 *    earlier rows are in the transaction, so a file that swaps two addresses
 *    between two clients is rejected on the second row.  Splitting it into two
 *    imports is the way through; guessing an order is not.
 *
 * Error codes: invalid_payload, storage_error, missing_request_id,
 * missing_preview_id, request_id_conflict, preview_not_found, preview_expired,
 * preview_stale, preview_has_no_valid_rows, missing_confirmation,
 * confirmation_mismatch, missing_expected_version, expected_version_mismatch,
 * permission_denied, runtime_executor_unavailable, apply_failed,
 * readback_mismatch, address_conflict, mac_conflict, ipam_address_write_failed,
 * dhcp_reservation_write_failed, transaction_busy, rollback_failed.
 */
struct json_object *jmx_ipam_import_commit(struct json_object *req)
{
    struct json_object *plan = NULL, *summary = NULL, *stored = NULL, *data = NULL;
    struct json_object *results = NULL, *rb = NULL, *rt_rb = NULL, *verify = NULL;
    struct json_object *envelope = NULL, *snapshot = NULL, *job = NULL, *nets = NULL;
    const char *preview_id, *request_id, *supplied_digest, *stored_digest, *net_hint;
    const char *stage = NULL, *code = NULL, *deny = NULL, *fail_reason = NULL;
    char bak[256] = "", job_id[80] = "", fingerprint[600];
    int conflict = 0, i, n = 0, failed_line = 0, rb_ok = 0, all_ok = 1, loaded;
    int checked = 0;
    int64_t expected, now;
    sqlite3_int64 revision, preview_rev = 0, rev_before;

    if (!req)
        return nc_ipamc_reject("invalid_payload", "request", 0);
    if (jmx_netconfig_db_init() != 0)
        return nc_ipamc_reject("storage_error", "storage", 0);
    nc_ipam_db_init();
    nc_ipamc_db_init();
    now = nc_now_s();
    revision = nc_ipam_revision();

    preview_id = nc_json_str_def(req, "preview_id", "");
    request_id = nc_json_str_def(req, "request_id", "");
    expected = nc_json_int64_def(req, "expected_version",
                                 nc_json_int64_def(req, "expected_revision", 0));
    supplied_digest = nc_json_str_def(req, "confirm_digest", "");
    if (!supplied_digest[0]) {
        struct json_object *confirm = NULL;
        if (json_object_object_get_ex(req, "confirm", &confirm) && confirm)
            supplied_digest = nc_json_str_def(confirm, "digest", "");
    }
    if (!request_id[0])
        return nc_ipamc_reject("missing_request_id", "validate", revision);
    if (!preview_id[0])
        return nc_ipamc_reject("missing_preview_id", "validate", revision);

    /*
     * Replay first, as in the single write: a commit that already succeeded must
     * keep answering with its original result even after the revision has moved
     * on, and the job row is re-read live so its status is never a stale copy.
     */
    snprintf(fingerprint, sizeof(fingerprint), "%s|%s|%lld", preview_id,
             supplied_digest, (long long)expected);
    stored = nc_ipamc_ledger_lookup(request_id, "import_commit", fingerprint, &conflict);
    if (conflict) {
        json_object_put(stored);
        return nc_ipamc_reject("request_id_conflict", "idempotency", revision);
    }
    if (stored) {
        job = nc_ipamc_job_json(nc_json_str_def(stored, "job_id", ""));
        json_object_object_add(stored, "replayed", json_object_new_boolean(1));
        json_object_object_add(stored, "job", job);
        return jmx_gen_api_response_data(API_CODE_SUCCESS, stored);
    }

    loaded = nc_ipamc_preview_load(preview_id, now, &plan, &summary, &preview_rev);
    if (loaded != 0) {
        json_object_put(plan);
        json_object_put(summary);
        return nc_ipamc_reject(loaded > 0 ? "preview_expired" : "preview_not_found",
                               "preview", revision);
    }
    n = (int)json_object_array_length(plan);
    stored_digest = nc_json_str_def(summary, "confirm_digest", "");
    net_hint = nc_json_str_def(req, "network_id", "");
    if (!net_hint[0] && json_object_object_get_ex(summary, "networks", &nets) && nets &&
        json_object_is_type(nets, json_type_array) &&
        json_object_array_length(nets) == 1)
        net_hint = json_object_get_string(json_object_array_get_idx(nets, 0));

    if (n <= 0) code = "preview_has_no_valid_rows";
    else if (!supplied_digest[0]) code = "missing_confirmation";
    else if (strcmp(supplied_digest, stored_digest)) code = "confirmation_mismatch";
    else if (expected < 1) code = "missing_expected_version";
    else if (expected != revision) code = "expected_version_mismatch";
    /*
     * The preview's verdicts were computed against preview_rev.  If the table has
     * moved since, every conflict check in it describes a state that no longer
     * exists -- re-validating silently here would apply something the user never
     * reviewed, so the client is sent back to preview instead.
     */
    else if (preview_rev != revision) code = "preview_stale";
    if (code) {
        json_object_put(plan);
        json_object_put(summary);
        return nc_ipamc_reject(code, "confirm", revision);
    }
    if (!nc_ipamc_runtime_writable(&deny)) {
        json_object_put(plan);
        json_object_put(summary);
        return nc_ipamc_reject((deny && !strcmp(deny, "permission_denied")) ?
                               "permission_denied" : "runtime_executor_unavailable",
                               "capability", revision);
    }

    rev_before = revision;
    nc_ipamc_new_id("imp", job_id, sizeof(job_id));
    nc_ipamc_job_store(job_id, preview_id, request_id, net_hint, "running", NULL,
                       NULL, rev_before, 0);

    if (nc_ipamc_batch_apply(plan, bak, sizeof(bak), &stage, &failed_line,
                             &fail_reason) != 0) {
        /*
         * A failed backup is the one case with nothing to undo: it happens before
         * the first write, so running the rollback would report a restore failure
         * for a file that was never touched.
         */
        if (fail_reason && !strcmp(fail_reason, "backup_failed")) {
            nc_ipamc_job_store(job_id, preview_id, request_id, net_hint, "failed",
                               "storage_error", NULL, rev_before, revision);
            json_object_put(plan);
            json_object_put(summary);
            return nc_ipamc_env_add(nc_ipamc_reject("storage_error", "backup", revision),
                                    "job_id", json_object_new_string(job_id));
        }
        results = json_object_new_array();
        for (i = 0; i < n; i++) {
            struct json_object *row = json_object_array_get_idx(plan, i);
            int is_failed = failed_line &&
                            nc_json_int_def(row, "line", i + 1) == failed_line;
            json_object_array_add(results,
                                  nc_ipamc_result_row(row, "not_applied",
                                                      is_failed ? fail_reason : NULL,
                                                      NULL));
        }
        code = "apply_failed";
        if (!stage) stage = "runtime_apply";
        goto undo;
    }

    /* Canonical config readback, per row, out of /etc/config/dhcp -- not out of the
     * plan we just wrote from. */
    results = json_object_new_array();
    for (i = 0; i < n; i++) {
        struct json_object *row = json_object_array_get_idx(plan, i);
        struct json_object *cfg;
        int row_ok = 0;

        cfg = nc_ipamc_host_readback(nc_json_str_def(row, "mac", ""),
                                     nc_json_str_def(row, "address", ""),
                                     nc_json_str_def(row, "name", ""), &row_ok);
        if (!row_ok) {
            all_ok = 0;
            if (!failed_line) failed_line = nc_json_int_def(row, "line", i + 1);
        }
        json_object_array_add(results,
                              nc_ipamc_result_row(row,
                                                  row_ok ? "config_applied" : "failed",
                                                  row_ok ? NULL : "readback_mismatch",
                                                  cfg));
        checked++;
    }
    rt_rb = nc_ipamc_runtime_readback();
    if (!all_ok) {
        code = "readback_mismatch";
        stage = "config_readback";
        goto undo;
    }
    if (!nc_dnsmasq_process_running()) {
        code = "apply_failed";
        stage = "runtime_readback";
        goto undo;
    }

    if (nc_exec("BEGIN IMMEDIATE") != 0) {
        code = "transaction_busy";
        stage = "database";
        goto undo;
    }
    if (nc_ipam_revision() != revision) {
        nc_exec("ROLLBACK");
        code = "expected_version_mismatch";
        stage = "database";
        goto undo;
    }
    for (i = 0; i < n; i++) {
        struct json_object *row = json_object_array_get_idx(plan, i);
        const char *nid = nc_json_str_def(row, "network_id", "");
        const char *ip = nc_json_str_def(row, "address", "");
        const char *macn = nc_json_str_def(row, "mac", "");
        const char *label = nc_json_str_def(row, "name", "");
        const char *host = nc_json_str_def(row, "hostname", "");
        const char *why = NULL;
        char prev[64] = "";

        /* Re-checked under the write lock: the preview and the pre-apply checks both
         * ran unlocked, so this is where a concurrent writer is caught. */
        if (nc_ipamc_conflicts(nid, ip, macn, prev, sizeof(prev), &why) != 0) {
            nc_exec("ROLLBACK");
            failed_line = nc_json_int_def(row, "line", i + 1);
            code = why ? why : "address_conflict";
            stage = "database";
            goto undo;
        }
        if (nc_ipamc_db_write(nid, ip, macn, host[0] ? host : label, label,
                              nc_json_str_def(row, "note", ""), prev, 0, &why) != 0) {
            nc_exec("ROLLBACK");
            failed_line = nc_json_int_def(row, "line", i + 1);
            code = why ? why : "storage_error";
            stage = "database";
            goto undo;
        }
    }
    if (nc_exec("UPDATE ipam_meta SET revision=revision+1") != 0) {
        nc_exec("ROLLBACK");
        code = "storage_error";
        stage = "revision";
        goto undo;
    }
    revision = nc_ipam_revision();
    if (nc_exec("COMMIT") != 0) {
        nc_exec("ROLLBACK");
        revision = nc_ipam_revision();      /* the bump did not survive the rollback */
        code = "storage_error";
        stage = "commit";
        goto undo;
    }
    nc_cleanup_backup(bak);
    for (i = 0; i < n; i++)
        json_object_object_add(json_object_array_get_idx(results, i), "status",
                               json_object_new_string("applied"));
    nc_ipamc_preview_consume(preview_id);

    verify = json_object_new_object();
    json_object_object_add(verify, "config_source",
                           json_object_new_string("/etc/config/dhcp"));
    json_object_object_add(verify, "config_rows_checked", json_object_new_int(checked));
    /* Per-row config readbacks are in results[].config_readback; this is the one
     * runtime observation, taken once after the single restart. */
    json_object_object_add(verify, "runtime", rt_rb);
    rt_rb = NULL;

    data = json_object_new_object();
    json_object_object_add(data, "ok", json_object_new_boolean(1));
    json_object_object_add(data, "error", NULL);
    json_object_object_add(data, "failure_stage", NULL);
    json_object_object_add(data, "job_id", json_object_new_string(job_id));
    json_object_object_add(data, "status", json_object_new_string("succeeded"));
    /* Not `queued`: the work is already done by the time this is read. */
    json_object_object_add(data, "execution", json_object_new_string("inline"));
    json_object_object_add(data, "preview_id", json_object_new_string(preview_id));
    json_object_object_add(data, "request_id", json_object_new_string(request_id));
    nc_ipamc_add_str_or_null(data, "network_id", net_hint);
    json_object_object_add(data, "rows_total", json_object_new_int(n));
    json_object_object_add(data, "rows_applied", json_object_new_int(n));
    json_object_object_add(data, "rows_failed", json_object_new_int(0));
    json_object_object_add(data, "revision_before", json_object_new_int64(rev_before));
    json_object_object_add(data, "revision", json_object_new_int64(revision));
    json_object_object_add(data, "config_applied", json_object_new_boolean(1));
    json_object_object_add(data, "runtime_applied", json_object_new_boolean(1));
    json_object_object_add(data, "rollback", nc_ipamc_rollback_none("not_needed"));
    json_object_object_add(data, "verify", verify);
    json_object_object_add(data, "results", json_object_get(results));
    json_object_object_add(data, "replayed", json_object_new_boolean(0));
    nc_ipamc_job_store(job_id, preview_id, request_id, net_hint, "succeeded", NULL,
                       results, rev_before, revision);
    json_object_put(results);
    results = NULL;
    /* Same as the single write: the ledger keeps the decision, and the table
     * snapshot is re-read fresh on every replay rather than stored. */
    nc_ipamc_ledger_store(request_id, "import_commit", net_hint, fingerprint, data);
    envelope = jmx_bulk_ip_get();
    if (envelope && json_object_object_get_ex(envelope, "data", &snapshot) && snapshot)
        snapshot = json_object_get(snapshot);
    else
        snapshot = json_object_new_object();
    if (envelope) json_object_put(envelope);
    json_object_object_add(data, "readback", snapshot);
    json_object_put(plan);
    json_object_put(summary);
    return jmx_gen_api_response_data(API_CODE_SUCCESS, data);

undo:
    /*
     * One backup, one restore, one restart -- the mirror image of the batch apply,
     * so /etc/config/dhcp can never keep part of the import.  The database side has
     * already rolled itself back wherever it was reached at all, and a failure
     * before the revision bump leaves the caller's expected_version still valid, so
     * the retry needs nothing but a fresh preview.
     */
    rb = nc_ipamc_rollback_uci(bak, &rb_ok, "/tmp/dw-ipam-import-rollback.log");
    nc_cleanup_backup(bak);
    /*
     * Per-row fates after the rollback, which are not the job's fate: rows the
     * apply never reached stay `not_applied`, rows that did get written become
     * `rolled_back`, and if the restore itself failed they are `left_applied` --
     * the file still holds them, and saying otherwise would send the operator to
     * the wrong recovery.
     */
    if (results) {
        int rn = (int)json_object_array_length(results);
        for (i = 0; i < rn; i++) {
            struct json_object *r = json_object_array_get_idx(results, i);
            if (!strcmp(nc_json_str_def(r, "status", ""), "not_applied")) continue;
            json_object_object_add(r, "status",
                                   json_object_new_string(rb_ok ? "rolled_back"
                                                                : "left_applied"));
        }
    }
    verify = json_object_new_object();
    json_object_object_add(verify, "config_source",
                           json_object_new_string("/etc/config/dhcp"));
    json_object_object_add(verify, "config_rows_checked", json_object_new_int(checked));
    /* The runtime observation taken before the rollback described the state that
     * failed; `runtime` is the state that exists now, after the restore. */
    if (rt_rb) json_object_object_add(verify, "runtime_before_rollback", rt_rb);
    rt_rb = NULL;
    json_object_object_add(verify, "runtime", nc_ipamc_runtime_readback());

    nc_ipamc_job_store(job_id, preview_id, request_id, net_hint,
                       rb_ok ? "rolled_back" : "failed",
                       rb_ok ? code : "rollback_failed", results, rev_before, revision);
    /*
     * Deliberately not stored in the idempotency ledger: a failed commit must be
     * re-runnable under the same request_id, and a stored failure would answer the
     * retry with the old error instead of trying again.
     */
    dw_report_config_commit_failed("ipam_reservation", job_id,
                                   rb_ok ? code : "rollback_failed", rb_ok);
    envelope = nc_ipamc_write_error(rb_ok ? code : "rollback_failed", stage, revision,
                                   rb_ok ? 0 : 1, 0, rb, verify);
    nc_ipamc_env_add(envelope, "job_id", json_object_new_string(job_id));
    nc_ipamc_env_add(envelope, "status",
                     json_object_new_string(rb_ok ? "rolled_back" : "failed"));
    nc_ipamc_env_add(envelope, "execution", json_object_new_string("inline"));
    nc_ipamc_env_add(envelope, "preview_id", json_object_new_string(preview_id));
    nc_ipamc_env_add(envelope, "request_id", json_object_new_string(request_id));
    nc_ipamc_env_add(envelope, "revision_before", json_object_new_int64(rev_before));
    nc_ipamc_env_add(envelope, "rows_total", json_object_new_int(n));
    nc_ipamc_env_add(envelope, "failed_line",
                     failed_line ? json_object_new_int(failed_line) : NULL);
    nc_ipamc_env_add(envelope, "results", results);
    nc_ipamc_env_add(envelope, "replayed", json_object_new_boolean(0));
    json_object_put(plan);
    json_object_put(summary);
    return envelope;
}

/* The legacy importer in 013 wrote counters and nothing else: no per-row results,
 * no readback, no rollback record.  Its jobs are still answerable, but they must
 * be answered as what they are -- `legacy: true`, runtime closure unknown -- or
 * the reader would claim a guarantee that import never provided. */
static struct json_object *nc_ipamc_legacy_job_json(const char *job_id)
{
    sqlite3_stmt *st = NULL;
    struct json_object *job = NULL;

    if (!nc_table_exists("ipam_import_job")) return NULL;
    if (nc_prepare(&st, "SELECT filename,rows,success,failed,error,created_at "
                        "FROM ipam_import_job WHERE id=?1") != 0)
        return NULL;
    sqlite3_bind_text(st, 1, job_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW) {
        int failed = sqlite3_column_int(st, 3);
        char iso[32];

        nc_ipamc_iso8601(sqlite3_column_int64(st, 5), iso, sizeof(iso));
        job = json_object_new_object();
        json_object_object_add(job, "job_id", json_object_new_string(job_id));
        json_object_object_add(job, "preview_id", NULL);
        json_object_object_add(job, "request_id", NULL);
        json_object_object_add(job, "network_id", NULL);
        json_object_object_add(job, "status",
                               json_object_new_string(failed ? "failed" : "succeeded"));
        nc_ipamc_add_col_or_null(job, "error", st, 4);
        nc_ipamc_add_col_or_null(job, "filename", st, 0);
        json_object_object_add(job, "rows_total",
                               json_object_new_int(sqlite3_column_int(st, 1)));
        json_object_object_add(job, "rows_applied",
                               json_object_new_int(sqlite3_column_int(st, 2)));
        json_object_object_add(job, "rows_failed", json_object_new_int(failed));
        json_object_object_add(job, "revision_before", NULL);
        json_object_object_add(job, "revision_after", NULL);
        nc_ipamc_add_str_or_null(job, "created_at", iso);
        nc_ipamc_add_str_or_null(job, "updated_at", iso);
        json_object_object_add(job, "results", json_object_new_array());
        json_object_object_add(job, "legacy", json_object_new_boolean(1));
    }
    sqlite3_finalize(st);
    return job;
}

/*
 * The rollback outcome a stored job implies.  Reconstructed from status+error
 * rather than reusing nc_ipamc_rollback_none(), which reports
 * `attempted:false, ok:true` -- true for a job that never needed one, and a
 * straight falsehood for a job that rolled back or whose rollback failed.
 *
 * `failed` has two producers and they are opposites: a backup that never
 * happened (nothing to undo) and a restore that did happen and did not work.
 * The recorded error separates them.
 */
static struct json_object *nc_ipamc_job_rollback_json(const char *status,
                                                     const char *error, int legacy)
{
    struct json_object *rb = json_object_new_object();
    int rolled = status && !strcmp(status, "rolled_back");
    int rb_failed = error && !strcmp(error, "rollback_failed");

    if (legacy) {
        /* The legacy importer had no rollback at all, so its outcome is unknown
         * rather than clean -- ok stays null. */
        json_object_object_add(rb, "attempted", NULL);
        json_object_object_add(rb, "ok", NULL);
        json_object_object_add(rb, "reason", json_object_new_string("not_recorded"));
        return rb;
    }
    json_object_object_add(rb, "attempted",
                           json_object_new_boolean(rolled || rb_failed));
    json_object_object_add(rb, "ok", json_object_new_boolean(!rb_failed));
    json_object_object_add(rb, "config_restored", json_object_new_boolean(rolled));
    json_object_object_add(rb, "reason",
                           json_object_new_string(rb_failed ? "rollback_failed" :
                               rolled ? "config_restored" :
                               (status && !strcmp(status, "succeeded")) ? "not_needed"
                                                                        : "nothing_applied"));
    return rb;
}

/*
 * GET /api/v1/bulk-ip/import/jobs/{job_id}
 *
 * Read-only.  Every claim in the response comes out of the job row the commit
 * wrote, so a job that never proved runtime closure cannot start claiming it
 * later: `runtime_applied` is derived from the recorded status, and for a legacy
 * job it is JSON null with a reason rather than false -- "not recorded" and "did
 * not happen" are different answers.
 *
 * Error codes: invalid_payload, missing_job_id, job_not_found, storage_error.
 */
struct json_object *jmx_ipam_import_job_get(struct json_object *req)
{
    struct json_object *job = NULL, *results = NULL, *data = NULL;
    const char *job_id;
    int legacy = 0, applied = 0, failed = 0, rolled = 0, not_applied = 0;
    int i, rn = 0, terminal;
    const char *status;
    sqlite3_int64 revision;

    if (!req)
        return nc_ipamc_reject("invalid_payload", "request", 0);
    if (jmx_netconfig_db_init() != 0)
        return nc_ipamc_reject("storage_error", "storage", 0);
    nc_ipam_db_init();
    nc_ipamc_db_init();
    revision = nc_ipam_revision();

    job_id = nc_json_str_def(req, "job_id", "");
    if (!job_id[0]) job_id = nc_json_str_def(req, "id", "");
    if (!job_id[0])
        return nc_ipamc_reject("missing_job_id", "validate", revision);

    job = nc_ipamc_job_json(job_id);
    if (!job) {
        job = nc_ipamc_legacy_job_json(job_id);
        legacy = job != NULL;
    }
    if (!job)
        return nc_ipamc_reject("job_not_found", "lookup", revision);

    status = nc_json_str_def(job, "status", "");
    if (json_object_object_get_ex(job, "results", &results) && results &&
        json_object_is_type(results, json_type_array))
        rn = (int)json_object_array_length(results);
    for (i = 0; i < rn; i++) {
        const char *rs = nc_json_str_def(json_object_array_get_idx(results, i),
                                         "status", "");
        if (!strcmp(rs, "applied") || !strcmp(rs, "config_applied")) applied++;
        else if (!strcmp(rs, "rolled_back")) rolled++;
        else if (!strcmp(rs, "not_applied")) not_applied++;
        else failed++;
    }
    if (!legacy) {
        json_object_object_add(job, "rows_total", json_object_new_int(rn));
        json_object_object_add(job, "rows_applied", json_object_new_int(applied));
        json_object_object_add(job, "rows_failed", json_object_new_int(failed));
        json_object_object_add(job, "rows_rolled_back", json_object_new_int(rolled));
        json_object_object_add(job, "rows_not_applied", json_object_new_int(not_applied));
    }
    terminal = strcmp(status, "queued") && strcmp(status, "running");
    json_object_object_add(job, "terminal", json_object_new_boolean(terminal));
    /*
     * config_applied / runtime_applied are the commit's recorded verdict, not a
     * fresh probe: this endpoint is a status read, and re-probing here would report
     * whatever the current state happens to be -- including someone else's later
     * write -- as if this job had done it.
     */
    if (legacy) {
        json_object_object_add(job, "config_applied", NULL);
        json_object_object_add(job, "runtime_applied", NULL);
        json_object_object_add(job, "runtime_closure",
                               json_object_new_string("not_recorded"));
    } else {
        int ok = !strcmp(status, "succeeded");
        json_object_object_add(job, "config_applied", json_object_new_boolean(ok));
        json_object_object_add(job, "runtime_applied", json_object_new_boolean(ok));
        json_object_object_add(job, "runtime_closure",
                               json_object_new_string(ok ? "verified" :
                                   (!strcmp(status, "rolled_back") ? "rolled_back"
                                                                   : "not_applied")));
    }
    json_object_object_add(job, "rollback",
                           nc_ipamc_job_rollback_json(status,
                                                      nc_json_str_def(job, "error", ""),
                                                      legacy));
    json_object_object_add(job, "execution", json_object_new_string("inline"));

    data = json_object_new_object();
    json_object_object_add(data, "ok", json_object_new_boolean(1));
    json_object_object_add(data, "error", NULL);
    json_object_object_add(data, "revision", json_object_new_int64(revision));
    json_object_object_add(data, "job", job);
    return jmx_gen_api_response_data(API_CODE_SUCCESS, data);
}




















