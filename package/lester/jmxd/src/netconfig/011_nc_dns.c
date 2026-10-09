/* ══════════════════════════════════════════════════════════════════════
 * DNS engine discovery (A-09 P1)
 *
 * Which resolvers exist is a runtime fact about the installed firmware, not a
 * compile-time constant. Hardcoding smartdns/mosdns to false made the API lie
 * on boxes that actually have them installed, and told the user "unsupported"
 * when the truthful answer is "installed but not wired up yet".
 *
 * We report three orthogonal facts per engine and never conflate them:
 *   installed - binary present
 *   managed   - init script present (we could start/stop it)
 *   active    - the process is actually running right now
 * "Can DreamingWrt drive it" is a fourth, separate thing, and is still false
 * until the renderer lands - see dns_engine_switch below.
 * ══════════════════════════════════════════════════════════════════════ */

#include "network_transaction_uci.h"

typedef struct {
    const char *id;
    const char *binary;
    const char *alt_binary;
    const char *init_script;
    const char *proc_name;
    int encrypted_upstreams;   /* engine itself can speak DoT/DoH upstream */
} nc_dns_engine_t;

static const nc_dns_engine_t g_dns_engines[] = {
    { "dnsmasq",     "/usr/sbin/dnsmasq",  NULL,
      "/etc/init.d/dnsmasq",     "dnsmasq",     0 },
    { "smartdns",    "/usr/sbin/smartdns", "/usr/bin/smartdns",
      "/etc/init.d/smartdns",    "smartdns",    1 },
    { "mosdns",      "/usr/bin/mosdns",    "/usr/sbin/mosdns",
      "/etc/init.d/mosdns",      "mosdns",      1 },
    { "adguardhome", "/usr/bin/AdGuardHome", "/usr/bin/adguardhome",
      "/etc/init.d/AdGuardHome", "AdGuardHome", 1 },
};
#define NC_DNS_ENGINE_COUNT ((int)(sizeof(g_dns_engines) / sizeof(g_dns_engines[0])))

static int nc_dns_engine_installed(const nc_dns_engine_t *e)
{
    if (!e) return 0;
    if (e->binary && access(e->binary, X_OK) == 0) return 1;
    if (e->alt_binary && access(e->alt_binary, X_OK) == 0) return 1;
    return 0;
}

static const char *nc_dns_engine_path(const nc_dns_engine_t *e)
{
    if (!e) return "";
    if (e->binary && access(e->binary, X_OK) == 0) return e->binary;
    if (e->alt_binary && access(e->alt_binary, X_OK) == 0) return e->alt_binary;
    return "";
}

/* Running or not - read from /proc, not from an init script exit code. */
static int nc_dns_engine_active(const nc_dns_engine_t *e)
{
    DIR *d;
    struct dirent *de;
    int found = 0;

    if (!e || !e->proc_name || !e->proc_name[0])
        return 0;
    d = opendir("/proc");
    if (!d)
        return 0;
    while (!found && (de = readdir(d))) {
        char path[64], comm[128];
        FILE *fp;
        if (de->d_name[0] < '0' || de->d_name[0] > '9')
            continue;
        if ((size_t)snprintf(path, sizeof(path), "/proc/%s/comm",
                             de->d_name) >= sizeof(path))
            continue;
        fp = fopen(path, "r");
        if (!fp)
            continue;
        if (fgets(comm, sizeof(comm), fp)) {
            char *nl = strchr(comm, '\n');
            if (nl) *nl = '\0';
            if (!strcmp(comm, e->proc_name))
                found = 1;
        }
        fclose(fp);
    }
    closedir(d);
    return found;
}

static const nc_dns_engine_t *nc_dns_engine_find(const char *id)
{
    int i;
    if (!id || !id[0]) return NULL;
    for (i = 0; i < NC_DNS_ENGINE_COUNT; i++)
        if (!strcmp(g_dns_engines[i].id, id))
            return &g_dns_engines[i];
    return NULL;
}

/*
 * True when some installed engine could carry encrypted upstreams. This is the
 * honest basis for the doh/dot capability: it is a property of the resolver in
 * use, not a global constant. dnsmasq alone cannot do it, so on a dnsmasq-only
 * box this stays false - which is why it used to be hardcoded 0.
 */
static int nc_dns_encrypted_capable_engine(const char **engine_id)
{
    int i;
    if (engine_id) *engine_id = "";
    for (i = 0; i < NC_DNS_ENGINE_COUNT; i++) {
        if (!g_dns_engines[i].encrypted_upstreams)
            continue;
        if (nc_dns_engine_installed(&g_dns_engines[i])) {
            if (engine_id) *engine_id = g_dns_engines[i].id;
            return 1;
        }
    }
    return 0;
}

/* Per-engine inventory for the UI, plus why a capability is off. */
static void nc_dns_add_engines(struct json_object *root)
{
    struct json_object *arr = json_object_new_array();
    int i;

    for (i = 0; i < NC_DNS_ENGINE_COUNT; i++) {
        const nc_dns_engine_t *e = &g_dns_engines[i];
        struct json_object *o = json_object_new_object();
        int installed = nc_dns_engine_installed(e);
        int managed = e->init_script && nc_file_exists(e->init_script);

        json_object_object_add(o, "id", json_object_new_string(e->id));
        json_object_object_add(o, "installed", json_object_new_boolean(installed));
        json_object_object_add(o, "path", json_object_new_string(nc_dns_engine_path(e)));
        json_object_object_add(o, "managed", json_object_new_boolean(managed));
        json_object_object_add(o, "active",
                               json_object_new_boolean(installed ? nc_dns_engine_active(e) : 0));
        json_object_object_add(o, "encrypted_upstreams",
                               json_object_new_boolean(e->encrypted_upstreams));
        /* DreamingWrt cannot yet render this engine's config; only dnsmasq is
         * driven end-to-end today. Say so instead of implying we can switch. */
        json_object_object_add(o, "dreamingwrt_managed_config",
                               json_object_new_boolean(!strcmp(e->id, "dnsmasq")));
        if (!installed)
            json_object_object_add(o, "reason", json_object_new_string("engine_not_installed"));
        else if (strcmp(e->id, "dnsmasq"))
            json_object_object_add(o, "reason",
                                   json_object_new_string("engine_config_renderer_missing"));
        json_object_array_add(arr, o);
    }
    json_object_object_add(root, "engines", arr);
}

static void nc_dns_add_caps(struct json_object *root)
{
    struct json_object *caps = json_object_new_object();
    const char *enc_engine = "";
    int enc_engine_present = nc_dns_encrypted_capable_engine(&enc_engine);
    const nc_dns_engine_t *e_smart = nc_dns_engine_find("smartdns");
    const nc_dns_engine_t *e_mos = nc_dns_engine_find("mosdns");

    json_object_object_add(caps, "dnsmasq", json_object_new_boolean(1));
    /* Installed-and-detected, from the runtime probe above. */
    json_object_object_add(caps, "smartdns",
                           json_object_new_boolean(nc_dns_engine_installed(e_smart)));
    json_object_object_add(caps, "mosdns",
                           json_object_new_boolean(nc_dns_engine_installed(e_mos)));
    /*
     * doh/dot describe whether *this box could* carry encrypted upstreams.
     * Writing one is still refused by nc_dns_request_capability_check() until
     * the renderer lands, which is reported separately as
     * encrypted_upstream_write so the UI cannot mistake one for the other.
     */
    json_object_object_add(caps, "doh", json_object_new_boolean(enc_engine_present));
    json_object_object_add(caps, "dot", json_object_new_boolean(enc_engine_present));
    json_object_object_add(caps, "encrypted_upstream_write", json_object_new_boolean(0));
    json_object_object_add(caps, "encrypted_upstream_engine",
                           json_object_new_string(enc_engine));
    if (!enc_engine_present)
        json_object_object_add(caps, "encrypted_upstream_reason",
            json_object_new_string("no_installed_engine_supports_encrypted_upstreams"));
    else
        json_object_object_add(caps, "encrypted_upstream_reason",
            json_object_new_string("engine_config_renderer_missing"));
    /* Switching the active resolver is not implemented; only dnsmasq is driven. */
    json_object_object_add(caps, "dns_engine_switch", json_object_new_boolean(0));
    json_object_object_add(caps, "domain_block", json_object_new_boolean(1));
    json_object_object_add(caps, "domain_forward", json_object_new_boolean(1));
    json_object_object_add(caps, "live_stats", json_object_new_boolean(0));
    json_object_object_add(caps, "conditional_forward", json_object_new_boolean(1));
    json_object_object_add(caps, "local_hosts", json_object_new_boolean(1));
    json_object_object_add(caps, "service_update", json_object_new_boolean(1));
    json_object_object_add(caps, "apply_readback", json_object_new_boolean(1));
    json_object_object_add(caps, "rollback", json_object_new_boolean(1));
    json_object_object_add(caps, "dns_redirect", json_object_new_boolean(0));
    json_object_object_add(caps, "hijack_protection", json_object_new_boolean(0));
    json_object_object_add(caps, "ecs", json_object_new_boolean(0));
    json_object_object_add(caps, "ipv6_dns", json_object_new_boolean(0));
    json_object_object_add(caps, "save_dns_rule", json_object_new_boolean(0));
    json_object_object_add(caps, "delete_dns_rule", json_object_new_boolean(0));
    json_object_object_add(caps, "upstreams_bulk_update", json_object_new_boolean(1));
    json_object_object_add(caps, "rules_bulk_update", json_object_new_boolean(1));
    json_object_object_add(caps, "upstream_rule", json_object_new_boolean(1));
    json_object_object_add(caps, "save_wan_dns_policy", json_object_new_boolean(1));
    json_object_object_add(caps, "wan_policy_read_by_wan", json_object_new_boolean(1));
    json_object_object_add(caps, "wan_policy_read_all", json_object_new_boolean(0));
    json_object_object_add(caps, "wan_policy_apply_readback", json_object_new_boolean(1));
    json_object_object_add(caps, "wan_policy_domains", json_object_new_boolean(1));
    json_object_object_add(caps, "wan_policy_domain_split_ipv4", json_object_new_boolean(1));
    json_object_object_add(caps, "wan_policy_domain_split_ipv6", json_object_new_boolean(0));
    json_object_object_add(root, "capabilities", caps);

    struct json_object *protos = json_object_new_array();
    json_object_array_add(protos, json_object_new_string("udp"));
    json_object_array_add(protos, json_object_new_string("tcp"));
    json_object_object_add(root, "supported_protocols", protos);
    /* marker: caps added */
}

struct json_object *jmx_dns_service_get(void)
{
    struct json_object *data = json_object_new_object();
    struct json_object *ifs = json_object_new_array();
    struct json_object *ups = json_object_new_array();
    struct json_object *rules = json_object_new_array();
    sqlite3_stmt *st = NULL;
    int configured = 0;
    int enabled = 0;
    int listen_port = 53;
    int runtime_ready = 0;
    int degraded = 0;
    char stored_apply_state[32] = "unknown";
    char last_apply_error[160] = "";
    char degraded_reason[160] = "";
    int64_t last_apply_at = 0;

    if (jmx_netconfig_db_init() != 0) goto done;
    if (nc_prepare(&st,
        "SELECT enabled,mode,listen_port,cache_enabled,cache_size,local_domain,"
        "rebind_protection,hijack_protection,edns_client_subnet,ipv6_dns "
        "FROM dns_service WHERE id=1") == 0) {
        if (sqlite3_step(st) == SQLITE_ROW) {
            configured = 1;
            enabled = sqlite3_column_int(st, 0);
            listen_port = sqlite3_column_int(st, 2);
            json_object_object_add(data, "enabled", json_object_new_boolean(enabled));
            nc_add_text(data, "mode", st, 1);
            json_object_object_add(data, "listen_port", json_object_new_int(sqlite3_column_int(st, 2)));
            json_object_object_add(data, "cache_enabled", json_object_new_boolean(sqlite3_column_int(st, 3)));
            json_object_object_add(data, "cache_size", json_object_new_int(sqlite3_column_int(st, 4)));
            nc_add_text(data, "local_domain", st, 5);
            json_object_object_add(data, "rebind_protection", json_object_new_boolean(sqlite3_column_int(st, 6)));
            json_object_object_add(data, "hijack_protection", json_object_new_boolean(sqlite3_column_int(st, 7)));
            json_object_object_add(data, "edns_client_subnet", json_object_new_boolean(sqlite3_column_int(st, 8)));
            json_object_object_add(data, "ipv6_dns", json_object_new_boolean(sqlite3_column_int(st, 9)));
        }
        sqlite3_finalize(st);
    }
    if (nc_prepare(&st, "SELECT lan_id FROM dns_listen_interface WHERE service_id=1 ORDER BY lan_id") == 0) {
        while (sqlite3_step(st) == SQLITE_ROW)
            json_object_array_add(ifs, json_object_new_string((const char *)sqlite3_column_text(st, 0)));
        sqlite3_finalize(st);
    }
    if (nc_prepare(&st, "SELECT id,name,address,port,protocol,group_name,enabled,sort_order FROM dns_upstream ORDER BY sort_order,id") == 0) {
        while (sqlite3_step(st) == SQLITE_ROW) {
            struct json_object *u = json_object_new_object();
            nc_add_text(u, "id", st, 0); nc_add_text(u, "name", st, 1); nc_add_text(u, "address", st, 2);
            json_object_object_add(u, "port", json_object_new_int(sqlite3_column_int(st, 3)));
            nc_add_text(u, "protocol", st, 4); nc_add_text(u, "group", st, 5);
            json_object_object_add(u, "enabled", json_object_new_boolean(sqlite3_column_int(st, 6)));
            json_object_object_add(u, "sort_order", json_object_new_int(sqlite3_column_int(st, 7)));
            json_object_object_add(u, "latency", json_object_new_int(0));
            json_object_array_add(ups, u);
        }
        sqlite3_finalize(st);
    }
    if (nc_prepare(&st, "SELECT id,domain,type,target,remark,enabled,sort_order FROM dns_rule ORDER BY sort_order,id") == 0) {
        while (sqlite3_step(st) == SQLITE_ROW) {
            struct json_object *r = json_object_new_object();
            nc_add_text(r, "id", st, 0); nc_add_text(r, "domain", st, 1); nc_add_text(r, "type", st, 2);
            nc_add_text(r, "target", st, 3); nc_add_text(r, "remark", st, 4);
            json_object_object_add(r, "enabled", json_object_new_boolean(sqlite3_column_int(st, 5)));
            json_object_object_add(r, "sort_order", json_object_new_int(sqlite3_column_int(st, 6)));
            json_object_array_add(rules, r);
        }
        sqlite3_finalize(st);
    }
done:
    nc_dns_apply_state_get(stored_apply_state, sizeof(stored_apply_state),
                           &last_apply_at, last_apply_error,
                           sizeof(last_apply_error));
    if (configured) {
        runtime_ready = !enabled || nc_dns_runtime_ready(listen_port, 0);
        degraded = nc_dns_config_degraded_reason(degraded_reason,
                                                  sizeof(degraded_reason));
    }

    /* Reconcile: if apply_state was never set but runtime confirms dnsmasq is
     * running with matching config, promote to applied.  This covers devices
     * whose DNS config came from UCI import and was never saved through the
     * web path. */
    if (!strcmp(stored_apply_state, "unknown") && configured &&
        runtime_ready && !degraded) {
        nc_dns_apply_state_set("applied", "");
        snprintf(stored_apply_state, sizeof(stored_apply_state), "applied");
    }
    json_object_object_add(data, "configured", json_object_new_boolean(configured));
    json_object_object_add(data, "running", json_object_new_boolean(enabled && runtime_ready));
    json_object_object_add(data, "valid", json_object_new_boolean(configured && !degraded));
    json_object_object_add(data, "degraded", json_object_new_boolean(degraded));
    json_object_object_add(data, "configuration_supported", json_object_new_boolean(!degraded));
    json_object_object_add(data, "applied", json_object_new_boolean(
        runtime_ready && !degraded && !strcmp(stored_apply_state, "applied")));
    json_object_object_add(data, "apply_state", json_object_new_string(
        !configured ? "unconfigured" :
        degraded ? "degraded" :
        strcmp(stored_apply_state, "applied") ? stored_apply_state :
        runtime_ready ? (enabled ? "applied" : "configured_disabled") : "degraded"));
    json_object_object_add(data, "runtime_reason", json_object_new_string(
        !configured ? "config_missing" :
        degraded ? degraded_reason :
        strcmp(stored_apply_state, "applied") ?
            (!strcmp(stored_apply_state, "unknown") ? "apply_state_never_recorded" :
             last_apply_error[0] ? last_apply_error : "configuration_not_runtime_verified") :
        runtime_ready ? "" : "dns_listener_not_ready"));
    json_object_object_add(data, "last_apply_at", json_object_new_int64(last_apply_at));
    json_object_object_add(data, "last_apply_error", json_object_new_string(last_apply_error));
    json_object_object_add(data, "runtime_source",
                           json_object_new_string(enabled ? "dnsmasq_process+dns_query:127.0.0.1:configured_port" : "config.db:disabled"));
    json_object_object_add(data, "ts", json_object_new_int64(nc_now_s()));
    json_object_object_add(data, "listen_interfaces", ifs);
    json_object_object_add(data, "upstreams", ups);
    json_object_object_add(data, "rules", rules);
    nc_dns_add_wan_dns(data);
    nc_dns_add_stats(data);
    nc_dns_add_caps(data);
    nc_dns_add_engines(data);
    return jmx_gen_api_response_data(API_CODE_SUCCESS, data);
}

static int nc_dns_request_capability_check(struct json_object *cfg)
{
    struct json_object *value = NULL;
    struct json_object *arr = NULL;
    int i, n;

    if (!cfg || jmx_netconfig_db_init() != 0)
        return -1;
    if (json_object_object_get_ex(cfg, "mode", &value) && value) {
        const char *requested_mode = json_object_get_string(value);
        if (!requested_mode || strcmp(requested_mode, "proxy")) {
            return -3;
        }
    }
    if ((json_object_object_get_ex(cfg, "hijack_protection", &value) && value &&
         json_object_get_boolean(value)) ||
        (json_object_object_get_ex(cfg, "edns_client_subnet", &value) && value &&
         json_object_get_boolean(value)) ||
        (json_object_object_get_ex(cfg, "ipv6_dns", &value) && value &&
         json_object_get_boolean(value))) {
        return -3;
    }

    if (json_object_object_get_ex(cfg, "upstreams", &arr) && arr &&
        json_object_is_type(arr, json_type_array)) {
        n = (int)json_object_array_length(arr);
        for (i = 0; i < n; i++) {
            struct json_object *upstream = json_object_array_get_idx(arr, i);
            const char *protocol = nc_json_str_def(upstream, "protocol", "udp");
            if (!strcmp(protocol, "dot") || !strcmp(protocol, "doh")) {
                sqlite3_stmt *existing = NULL;
                int transition_allowed = 0;
                const char *id = nc_json_str_def(upstream, "id", "");
                const char *name = nc_json_str_def(upstream, "name", id);
                const char *address = nc_json_str_def(upstream, "address", "");
                const char *group = nc_json_str_def(upstream, "group",
                    nc_json_str_def(upstream, "group_name", "默认"));
                int port = nc_json_int_def(upstream, "port", 53);
                int enabled = nc_json_bool_def(upstream, "enabled", 1);

                if (id[0] && nc_prepare(&existing,
                    "SELECT 1 FROM dns_upstream WHERE id=?1 AND name=?2 AND address=?3 "
                    "AND port=?4 AND protocol=?5 AND group_name=?6 LIMIT 1") == 0) {
                    sqlite3_bind_text(existing, 1, id, -1, SQLITE_TRANSIENT);
                    sqlite3_bind_text(existing, 2, name, -1, SQLITE_TRANSIENT);
                    sqlite3_bind_text(existing, 3, address, -1, SQLITE_TRANSIENT);
                    sqlite3_bind_int(existing, 4, port);
                    sqlite3_bind_text(existing, 5, protocol, -1, SQLITE_TRANSIENT);
                    sqlite3_bind_text(existing, 6, group, -1, SQLITE_TRANSIENT);
                    transition_allowed = sqlite3_step(existing) == SQLITE_ROW && !enabled;
                    sqlite3_finalize(existing);
                }
                if (!transition_allowed)
                    return -4;
            }
            if (strcmp(protocol, "udp") && strcmp(protocol, "tcp"))
                continue;
        }
    }
    if (json_object_object_get_ex(cfg, "rules", &arr) && arr &&
        json_object_is_type(arr, json_type_array)) {
        n = (int)json_object_array_length(arr);
        for (i = 0; i < n; i++) {
            struct json_object *rule = json_object_array_get_idx(arr, i);
            const char *type = nc_json_str_def(rule, "type", "");
            if (!nc_dns_valid_rule_type(type))
                return -2;
        }
    }
    return 0;
}

static int nc_dns_service_validate(struct json_object *cfg, int enforce_capabilities)
{
    struct json_object *arr = NULL;
    int i, n;
    int rc;
    if (!cfg) return -1;
    if (jmx_netconfig_db_init() != 0) return -1;
    if (enforce_capabilities) {
        if (!nc_dns_complete_snapshot(cfg))
            return -7;
        rc = nc_dns_request_capability_check(cfg);
        if (rc != 0) return rc;
        if (!nc_dns_listen_interfaces_valid(cfg))
            return -8;
    }

    /* Validate */
    int listen_port = nc_json_int_def(cfg, "listen_port", 53);
    int cache_size = nc_json_int_def(cfg, "cache_size", 4096);
    const char *local_domain = nc_json_str_def(cfg, "local_domain", "lan");
    if (listen_port < 1 || listen_port > 65535) { errno = EINVAL; return -2; }
    if (cache_size < 0 || cache_size > 1000000) { errno = EINVAL; return -2; }
    if (!local_domain[0] || !nc_dns_is_valid_host(local_domain) ||
        strchr(local_domain, ':') || strchr(local_domain, '[') || strchr(local_domain, ']')) {
        errno = EINVAL;
        return -2;
    }

    if (json_object_object_get_ex(cfg, "upstreams", &arr) && arr &&
        json_object_is_type(arr, json_type_array)) {
        n = (int)json_object_array_length(arr);
        for (i = 0; i < n; i++) {
            struct json_object *upstream = json_object_array_get_idx(arr, i);
            if (!upstream || !json_object_is_type(upstream, json_type_object) ||
                !nc_json_str_def(upstream, "id", "")[0] ||
                !(enforce_capabilities ? nc_dns_valid_upstream_request(upstream) :
                  nc_dns_valid_upstream_stored(upstream)))
                return -2;
            for (int j = 0; j < i; j++) {
                struct json_object *previous = json_object_array_get_idx(arr, j);
                if (previous && !strcmp(nc_json_str_def(previous, "id", ""),
                                        nc_json_str_def(upstream, "id", "")))
                    return -2;
            }
        }
    }
    if (json_object_object_get_ex(cfg, "rules", &arr) && arr &&
        json_object_is_type(arr, json_type_array)) {
        n = (int)json_object_array_length(arr);
        for (i = 0; i < n; i++) {
            struct json_object *rule = json_object_array_get_idx(arr, i);
            const char *type = nc_json_str_def(rule, "type", "");
            const char *domain = nc_json_str_def(rule, "domain", "");
            if (!rule || !json_object_is_type(rule, json_type_object) ||
                !nc_json_str_def(rule, "id", "")[0] || !domain[0] ||
                !(enforce_capabilities ? nc_dns_valid_domain_rule(rule) :
                  nc_dns_valid_rule_type_stored(type)))
                return -2;
            for (int j = 0; j < i; j++) {
                struct json_object *previous = json_object_array_get_idx(arr, j);
                if (previous &&
                    (!strcmp(nc_json_str_def(previous, "id", ""),
                             nc_json_str_def(rule, "id", "")) ||
                     (!strcmp(nc_json_str_def(previous, "domain", ""), domain) &&
                      !strcmp(nc_json_str_def(previous, "type", ""), type))))
                    return -2;
            }
        }
    }

    return 0;
}

static int nc_dns_service_set_internal(struct json_object *cfg, int enforce_capabilities)
{
    sqlite3_stmt *st = NULL;
    struct json_object *arr = NULL;
    int i, n;
    int rc = nc_dns_service_validate(cfg, enforce_capabilities);
    int own_transaction;
    if (rc != 0) return rc;
    own_transaction = sqlite3_get_autocommit(g_netconfig_db);
    if (own_transaction && nc_exec("BEGIN IMMEDIATE") != 0) return -1;
    rc = -1;
    if (nc_prepare(&st,
        "INSERT INTO dns_service(id,enabled,mode,listen_port,cache_enabled,cache_size,local_domain,"
        "rebind_protection,hijack_protection,edns_client_subnet,ipv6_dns,updated_at) "
        "VALUES(1,?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11) "
        "ON CONFLICT(id) DO UPDATE SET enabled=excluded.enabled,mode=excluded.mode,listen_port=excluded.listen_port,"
        "cache_enabled=excluded.cache_enabled,cache_size=excluded.cache_size,local_domain=excluded.local_domain,"
        "rebind_protection=excluded.rebind_protection,hijack_protection=excluded.hijack_protection,"
        "edns_client_subnet=excluded.edns_client_subnet,ipv6_dns=excluded.ipv6_dns,updated_at=excluded.updated_at") == 0) {
        sqlite3_bind_int(st, 1, nc_json_bool_def(cfg, "enabled", 1));
        sqlite3_bind_text(st, 2, nc_json_str_def(cfg, "mode", "proxy"), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 3, nc_json_int_def(cfg, "listen_port", 53));
        sqlite3_bind_int(st, 4, nc_json_bool_def(cfg, "cache_enabled", 1));
        sqlite3_bind_int(st, 5, nc_json_int_def(cfg, "cache_size", 4096));
        sqlite3_bind_text(st, 6, nc_json_str_def(cfg, "local_domain", "lan"), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 7, nc_json_bool_def(cfg, "rebind_protection", 1));
        sqlite3_bind_int(st, 8, nc_json_bool_def(cfg, "hijack_protection", 0));
        sqlite3_bind_int(st, 9, nc_json_bool_def(cfg, "edns_client_subnet", 0));
        sqlite3_bind_int(st, 10, nc_json_bool_def(cfg, "ipv6_dns", 0));
        sqlite3_bind_int64(st, 11, nc_now_s());
        if (nc_step_done(st) == 0) rc = 0;
        sqlite3_finalize(st);
    }
    if (rc == 0 && nc_prepare(&st, "DELETE FROM dns_listen_interface WHERE service_id=1") == 0) {
        if (nc_step_done(st) != 0) rc = -1;
        sqlite3_finalize(st);
        if (json_object_object_get_ex(cfg, "listen_interfaces", &arr) && arr && json_object_is_type(arr, json_type_array)) {
            n = (int)json_object_array_length(arr);
            for (i = 0; i < n; i++) {
                const char *lan = json_object_get_string(json_object_array_get_idx(arr, i));
                if (!lan || !lan[0]) continue;
                if (nc_prepare(&st, "INSERT OR IGNORE INTO dns_listen_interface(service_id,lan_id) VALUES(1,?1)") == 0) {
                    sqlite3_bind_text(st, 1, lan, -1, SQLITE_TRANSIENT);
                    if (nc_step_done(st) != 0) rc = -1;
                    sqlite3_finalize(st);
                } else rc = -1;
                if (rc != 0) break;
            }
        }
    } else if (rc == 0) rc = -1;
    if (rc == 0 && json_object_object_get_ex(cfg, "upstreams", &arr) && arr && json_object_is_type(arr, json_type_array)) {
        if (nc_prepare(&st, "DELETE FROM dns_upstream") != 0) rc = -1;
        else {
            if (nc_step_done(st) != 0) rc = -1;
            sqlite3_finalize(st);
        }
        n = (int)json_object_array_length(arr);
        for (i = 0; rc == 0 && i < n; i++) {
            struct json_object *u = json_object_array_get_idx(arr, i);
            if (!u || !json_object_is_type(u, json_type_object)) continue;
            if (nc_prepare(&st,
                "INSERT INTO dns_upstream(id,name,address,port,protocol,group_name,enabled,sort_order) "
                "VALUES(?1,?2,?3,?4,?5,?6,?7,?8)") != 0) { rc = -1; break; }
            const char *id = nc_json_str_def(u, "id", "");
            const char *addr = nc_json_str_def(u, "address", "");
            const char *proto = nc_json_str_def(u, "protocol", "udp");
            if (!id[0] || (enforce_capabilities ?
                !nc_dns_valid_upstream_request(u) : !nc_dns_valid_upstream_stored(u))) {
                sqlite3_finalize(st); rc = -1; break;
            }
            sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 2, nc_json_str_def(u, "name", id), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 3, addr, -1, SQLITE_TRANSIENT);
            sqlite3_bind_int(st, 4, nc_json_int_def(u, "port", 53));
            sqlite3_bind_text(st, 5, proto, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 6, nc_json_str_def(u, "group", nc_json_str_def(u, "group_name", "默认")), -1, SQLITE_TRANSIENT);
            sqlite3_bind_int(st, 7, nc_json_bool_def(u, "enabled", 1));
            sqlite3_bind_int(st, 8, nc_json_int_def(u, "sort_order", i));
            if (nc_step_done(st) != 0) rc = -1;
            sqlite3_finalize(st);
            if (rc != 0) break;
        }
    }
    if (rc == 0 && json_object_object_get_ex(cfg, "rules", &arr) && arr && json_object_is_type(arr, json_type_array)) {
        if (nc_prepare(&st, "DELETE FROM dns_rule") != 0) rc = -1;
        else {
            if (nc_step_done(st) != 0) rc = -1;
            sqlite3_finalize(st);
        }
        n = (int)json_object_array_length(arr);
        for (i = 0; rc == 0 && i < n; i++) {
            struct json_object *r = json_object_array_get_idx(arr, i);
            if (!r || !json_object_is_type(r, json_type_object)) continue;
            if (nc_prepare(&st,
                "INSERT INTO dns_rule(id,domain,type,target,remark,enabled,sort_order) "
                "VALUES(?1,?2,?3,?4,?5,?6,?7)") != 0) { rc = -1; break; }
            const char *id = nc_json_str_def(r, "id", "");
            const char *domain = nc_json_str_def(r, "domain", "");
            const char *type = nc_json_str_def(r, "type", "");
            if (!id[0] || !(enforce_capabilities ? nc_dns_valid_domain_rule(r) :
                (nc_dns_valid_rule_type_stored(type) && domain[0]))) {
                sqlite3_finalize(st); rc = -1; break;
            }
            sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 2, domain, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 3, type, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 4, nc_json_str_def(r, "target", ""), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 5, nc_json_str_def(r, "remark", ""), -1, SQLITE_TRANSIENT);
            sqlite3_bind_int(st, 6, nc_json_bool_def(r, "enabled", 1));
            sqlite3_bind_int(st, 7, nc_json_int_def(r, "sort_order", i));
            if (nc_step_done(st) != 0) rc = -1;
            sqlite3_finalize(st);
            if (rc != 0) break;
        }
    }
    if (rc == 0) nc_dns_apply_state_set("pending", "runtime_apply_required");
    if (own_transaction) {
        if (rc == 0 && nc_exec("COMMIT") != 0) rc = -1;
        if (rc != 0) nc_exec("ROLLBACK");
    }
    return rc;
}

int jmx_dns_service_set(struct json_object *cfg)
{
    return nc_dns_service_set_internal(cfg, 1);
}

int jmx_dns_service_save_apply(struct json_object *payload, int apply)
{
    struct json_object *resp = jmx_dns_service_save_apply_result(payload, apply);
    struct json_object *code = NULL;
    int ok = resp && json_object_object_get_ex(resp, "code", &code) && code &&
             json_object_get_int(code) == API_CODE_SUCCESS;
    if (resp) json_object_put(resp);
    return ok ? 0 : -1;
}

static struct json_object *nc_dns_snapshot_data(void)
{
    struct json_object *resp = jmx_dns_service_get();
    struct json_object *data = NULL;
    struct json_object *snapshot = NULL;

    if (resp && json_object_object_get_ex(resp, "data", &data) && data)
        snapshot = json_object_get(data);
    if (resp) json_object_put(resp);
    return snapshot;
}

static int nc_dns_restore_snapshot(struct json_object *snapshot)
{
    struct json_object *wan_dns = NULL;

    if (!snapshot || !nc_dns_snapshot_restorable(snapshot) ||
        nc_dns_service_set_internal(snapshot, 0) != 0)
        return -1;
    if (json_object_object_get_ex(snapshot, "wan_dns", &wan_dns) && wan_dns &&
        json_object_is_type(wan_dns, json_type_array) &&
        jmx_wan_dns_split_save_from_array(wan_dns) != 0)
        return -1;
    return jmx_dns_service_apply();
}

struct json_object *jmx_dns_service_save_apply_result(struct json_object *payload, int apply)
{
    struct json_object *cfg = NULL;
    struct json_object *wan_dns = NULL;
    struct json_object *before = nc_dns_snapshot_data();
    struct json_object *readback = NULL;
    struct json_object *readback_data = NULL;
    struct json_object *data = json_object_new_object();
    struct json_object *reloads = json_object_new_array();
    struct json_object *warnings = json_object_new_array();
    int saved = -1, applied = -1, rolled_back = 0, degraded = 0;
    char degraded_reason[160] = "";
    int ok;
    const char *error = NULL;
    const char *reason = NULL;

    if (!payload) goto done;
    if (!before || !nc_dns_snapshot_restorable(before)) {
        saved = -9;
        error = "storage_unavailable";
        reason = "complete_dns_rollback_snapshot_unavailable";
        goto done;
    }
    json_object_object_get_ex(payload, "config", &cfg);
    if (!cfg) cfg = payload;
    saved = jmx_dns_service_set(cfg);
    if (saved == 0 && cfg && json_object_object_get_ex(cfg, "wan_dns", &wan_dns) &&
        wan_dns && json_object_is_type(wan_dns, json_type_array) &&
        jmx_wan_dns_split_save_from_array(wan_dns) != 0) {
        saved = -6;
    }
    if (saved == -3) {
        error = "capability_disabled";
        reason = "dns_mode_or_field_runtime_consumer_pending";
    } else if (saved == -4) {
        error = "capability_disabled";
        reason = "dns_transport_runtime_consumer_pending";
    } else if (saved == -5) {
        error = "capability_disabled";
        reason = "dns_rule_type_runtime_consumer_pending";
    } else if (saved == -6) {
        error = "dns_wan_aggregate_save_failed";
        reason = "wan_dns_transaction_failed";
    } else if (saved == -7) {
        error = "dns_snapshot_incomplete";
        reason = "complete_dns_snapshot_required_for_rollback";
    } else if (saved == -8) {
        error = "dns_listen_interface_invalid";
        reason = "enabled_dns_requires_existing_enabled_lan";
    } else if (saved == -2) {
        error = "dns_validation_failed";
        reason = "request_validation_failed_before_write";
    } else if (saved != 0) {
        error = "dns_save_failed";
        reason = "storage_transaction_failed";
    }
    if (saved == 0 && apply) {
        applied = jmx_dns_service_apply();
        if (applied == 0)
            json_object_array_add(reloads, json_object_new_string("dnsmasq"));
        else {
            error = "dns_apply_failed";
            reason = "dnsmasq_restart_or_listener_readback_failed";
        }
    } else if (saved == 0) {
        applied = -2;
    }
done:
    if ((saved == -6 || (saved == 0 && apply && applied != 0)) && before)
        rolled_back = nc_dns_restore_snapshot(before) == 0;
    if (saved == 0)
        degraded = nc_dns_config_degraded_reason(degraded_reason,
                                                  sizeof(degraded_reason));
    ok = saved == 0 && (!apply || applied == 0);
    if (!ok)
        json_object_array_add(warnings, json_object_new_string(
            error ? error : "dns_save_apply_failed"));
    readback = jmx_dns_service_get();
    json_object_object_add(data, "ok", json_object_new_boolean(ok));
    json_object_object_add(data, "saved", json_object_new_boolean(saved == 0 && !rolled_back));
    json_object_object_add(data, "persisted", json_object_new_boolean(saved == 0 && !rolled_back));
    json_object_object_add(data, "save_attempted", json_object_new_boolean(saved == 0 || saved == -6));
    json_object_object_add(data, "applied", json_object_new_boolean(
        apply && applied == 0 && !degraded));
    json_object_object_add(data, "supported_subset_applied", json_object_new_boolean(
        apply && applied == 0));
    json_object_object_add(data, "degraded", json_object_new_boolean(degraded));
    json_object_object_add(data, "apply", json_object_new_boolean(!!apply));
    json_object_object_add(data, "runtime_rolled_back", json_object_new_boolean(rolled_back));
    json_object_object_add(data, "reload", reloads);
    json_object_object_add(data, "warnings", warnings);
    json_object_object_add(data, "apply_state", json_object_new_string(
        ok ? (degraded ? "degraded" : apply ? "applied" : "saved") :
        rolled_back ? "failed_rolled_back" : "failed"));
    if (degraded) {
        json_object_array_add(warnings, json_object_new_string(degraded_reason));
        json_object_object_add(data, "runtime_reason",
                               json_object_new_string(degraded_reason));
    }
    if (error) json_object_object_add(data, "error", json_object_new_string(error));
    if (reason) json_object_object_add(data, "reason", json_object_new_string(reason));
    if (error && !strcmp(error, "capability_disabled"))
        json_object_object_add(data, "capability", json_object_new_string(
            saved == -4 ? "dns_transport" : saved == -5 ? "dns_rule_type" : "dns_advanced_fields"));
    if (readback && json_object_object_get_ex(readback, "data", &readback_data) && readback_data)
        json_object_object_add(data, "readback", json_object_get(readback_data));
    if (readback) json_object_put(readback);
    if (before) json_object_put(before);
    return jmx_gen_api_response_data(ok ? API_CODE_SUCCESS : API_CODE_ERROR, data);
}

int jmx_dns_upstream_set(struct json_object *u)
{
    sqlite3_stmt *st = NULL;
    const char *id, *addr, *proto;
    if (!u) return -1;
    id = nc_json_str_def(u, "id", "");
    addr = nc_json_str_def(u, "address", "");
    proto = nc_json_str_def(u, "protocol", "udp");
    if (!id[0] || !addr[0] || !nc_dns_valid_protocol(proto)) return -3;
    if (jmx_netconfig_db_init() != 0) return -1;
    if (nc_prepare(&st,
        "INSERT INTO dns_upstream(id,name,address,port,protocol,group_name,enabled,sort_order) "
        "VALUES(?1,?2,?3,?4,?5,?6,?7,?8) "
        "ON CONFLICT(id) DO UPDATE SET name=excluded.name,address=excluded.address,port=excluded.port,"
        "protocol=excluded.protocol,group_name=excluded.group_name,enabled=excluded.enabled,sort_order=excluded.sort_order") != 0) return -1;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, nc_json_str_def(u, "name", id), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, addr, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 4, nc_json_int_def(u, "port", 53));
    sqlite3_bind_text(st, 5, proto, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 6, nc_json_str_def(u, "group", nc_json_str_def(u, "group_name", "默认")), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 7, nc_json_bool_def(u, "enabled", 1));
    sqlite3_bind_int(st, 8, nc_json_int_def(u, "sort_order", 0));
    int rc = nc_step_done(st); sqlite3_finalize(st); return rc;
}

int jmx_dns_rule_set(struct json_object *r)
{
    sqlite3_stmt *st = NULL;
    const char *id, *domain, *type;
    if (!r) return -1;
    id = nc_json_str_def(r, "id", "");
    domain = nc_json_str_def(r, "domain", "");
    type = nc_json_str_def(r, "type", "");
    if (!id[0] || !domain[0] || !nc_dns_valid_rule_type(type)) return -1;
    if (jmx_netconfig_db_init() != 0) return -1;
    if (nc_prepare(&st,
        "INSERT INTO dns_rule(id,domain,type,target,remark,enabled,sort_order) "
        "VALUES(?1,?2,?3,?4,?5,?6,?7) "
        "ON CONFLICT(id) DO UPDATE SET domain=excluded.domain,type=excluded.type,target=excluded.target,"
        "remark=excluded.remark,enabled=excluded.enabled,sort_order=excluded.sort_order") != 0) return -1;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, domain, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, type, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 4, nc_json_str_def(r, "target", ""), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 5, nc_json_str_def(r, "remark", ""), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 6, nc_json_bool_def(r, "enabled", 1));
    sqlite3_bind_int(st, 7, nc_json_int_def(r, "sort_order", 0));
    int rc = nc_step_done(st); sqlite3_finalize(st); return rc;
}

int jmx_dns_rule_delete(const char *id)
{
    sqlite3_stmt *st = NULL;
    if (!id || !id[0]) return -1;
    if (jmx_netconfig_db_init() != 0) return -1;
    if (nc_prepare(&st, "DELETE FROM dns_rule WHERE id=?1") != 0) return -1;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    int rc = nc_step_done(st); sqlite3_finalize(st); return rc;
}

static int nc_dns_service_apply_scoped(struct json_object *patch,
                                       struct json_object *prepared)
{
    struct uci_context *ctx = NULL;
    struct uci_package *pkg = NULL;
    sqlite3_stmt *st = NULL;
    char bak_dhcp[256] = {0};
    int rc = -1;
    int committed = 0;
    int enabled = 0;
    int port = 53;
    char b[512];
    struct json_object *value = NULL;
    int write_port = !patch || json_object_object_get_ex(patch, "enabled", &value) ||
        json_object_object_get_ex(patch, "listen_port", &value);
    int write_cache = !patch || json_object_object_get_ex(patch, "cache_enabled", &value) ||
        json_object_object_get_ex(patch, "cache_size", &value);
    int write_domain = !patch || json_object_object_get_ex(patch, "local_domain", &value);
    int write_rebind = !patch || json_object_object_get_ex(patch, "rebind_protection", &value);
    int write_listeners = !patch || json_object_object_get_ex(patch, "listen_interfaces", &value);
    int write_upstreams = !patch || json_object_object_get_ex(patch, "upstreams", &value);
    if (jmx_netconfig_db_init() != 0) return -1;
    if (!prepared && nc_backup_config("dhcp", bak_dhcp, sizeof(bak_dhcp)) != 0)
        return -1;
    ctx = uci_alloc_context();
    if (!ctx) goto done;
    if (uci_load(ctx, "dhcp", &pkg) != UCI_OK) goto done;
    if (nc_uci_ensure_section(ctx, pkg, "dhcp", "@dnsmasq[0]", "dnsmasq") != 0)
        goto done;
    if (nc_prepare(&st,
        "SELECT enabled,listen_port,cache_enabled,cache_size,local_domain,rebind_protection FROM dns_service WHERE id=1") == 0) {
        if (sqlite3_step(st) == SQLITE_ROW) {
            enabled = sqlite3_column_int(st, 0);
            port = sqlite3_column_int(st, 1);
            int cache_enabled = sqlite3_column_int(st, 2);
            int cache_size = sqlite3_column_int(st, 3);
            const char *domain = (const char *)sqlite3_column_text(st, 4);
            int rebind = sqlite3_column_int(st, 5);
            if (write_port) {
                snprintf(b, sizeof(b), "%d", enabled ? port : 0);
                if (nc_uci_set_pkg(ctx, "dhcp", "@dnsmasq[0]", "port", b) != 0) goto done;
            }
            if (write_cache) {
                snprintf(b, sizeof(b), "%d", cache_enabled ? cache_size : 0);
                if (nc_uci_set_pkg(ctx, "dhcp", "@dnsmasq[0]", "cachesize", b) != 0) goto done;
            }
            if (write_domain) {
                if (nc_uci_set_pkg(ctx, "dhcp", "@dnsmasq[0]", "domain", domain && domain[0] ? domain : "lan") != 0)
                    goto done;
                snprintf(b, sizeof(b), "/%s/", domain && domain[0] ? domain : "lan");
                if (nc_uci_set_pkg(ctx, "dhcp", "@dnsmasq[0]", "local", b) != 0 ||
                    nc_uci_set_pkg(ctx, "dhcp", "@dnsmasq[0]", "domainneeded", "1") != 0)
                    goto done;
            }
            if (write_rebind &&
                nc_uci_set_pkg(ctx, "dhcp", "@dnsmasq[0]", "rebind_protection", rebind ? "1" : "0") != 0)
                goto done;
        } else goto done;
        sqlite3_finalize(st);
        st = NULL;
    } else goto done;
    if (write_listeners) {
        if (nc_uci_delete_pkg(ctx, "dhcp", "@dnsmasq[0]", "interface") != 0) goto done;
        if (nc_prepare(&st, "SELECT lan_id FROM dns_listen_interface WHERE service_id=1 ORDER BY lan_id") == 0) {
            while (sqlite3_step(st) == SQLITE_ROW) {
                const char *lan = (const char *)sqlite3_column_text(st, 0);
                if (lan && lan[0] &&
                    nc_uci_add_list_pkg(ctx, "dhcp", "@dnsmasq[0]", "interface", lan) != 0)
                    goto done;
            }
            sqlite3_finalize(st);
            st = NULL;
        } else goto done;
    }
    if ((write_upstreams && nc_uci_delete_pkg(ctx, "dhcp", "@dnsmasq[0]", "server") != 0) ||
        (!patch && nc_uci_delete_pkg(ctx, "dhcp", "@dnsmasq[0]", "address") != 0))
        goto done;
    if (write_upstreams) {
    if (nc_prepare(&st, "SELECT address,port,protocol FROM dns_upstream WHERE enabled=1 ORDER BY sort_order,id") == 0) {
        while (sqlite3_step(st) == SQLITE_ROW) {
            const char *addr = (const char *)sqlite3_column_text(st, 0);
            int port = sqlite3_column_int(st, 1);
            const char *proto = (const char *)sqlite3_column_text(st, 2);
            if (!addr || !addr[0]) continue;
            if (proto && strcmp(proto, "udp") && strcmp(proto, "tcp")) {
                if (!strcmp(proto, "doh") || !strcmp(proto, "dot"))
                    continue;
                goto done;
            }
            snprintf(b, sizeof(b), "%s%s%d", addr, port > 0 ? "#" : "", port > 0 ? port : 53);
            if (nc_uci_add_list_pkg(ctx, "dhcp", "@dnsmasq[0]", "server", b) != 0) goto done;
        }
        sqlite3_finalize(st);
        st = NULL;
    } else goto done;
    if (nc_prepare(&st, "SELECT domain,type,target FROM dns_rule WHERE enabled=1 ORDER BY sort_order,id") == 0) {
        while (sqlite3_step(st) == SQLITE_ROW) {
            const char *domain = (const char *)sqlite3_column_text(st, 0);
            const char *type = (const char *)sqlite3_column_text(st, 1);
            const char *target = (const char *)sqlite3_column_text(st, 2);
            if (!domain || !domain[0] || !type) continue;
            if (!strcmp(type, "host")) {
                if (patch) continue;
                snprintf(b, sizeof(b), "/%s/%s", domain, target && target[0] ? target : "0.0.0.0");
                if (nc_uci_add_list_pkg(ctx, "dhcp", "@dnsmasq[0]", "address", b) != 0) goto done;
            } else if (!strcmp(type, "block")) {
                if (patch) continue;
                snprintf(b, sizeof(b), "/%s/0.0.0.0", domain);
                if (nc_uci_add_list_pkg(ctx, "dhcp", "@dnsmasq[0]", "address", b) != 0) goto done;
            } else if (!strcmp(type, "forward") || !strcmp(type, "upstream")) {
                snprintf(b, sizeof(b), "/%s/%s", domain, target && target[0] ? target : "");
                if (nc_uci_add_list_pkg(ctx, "dhcp", "@dnsmasq[0]", "server", b) != 0) goto done;
            } else goto done;
        }
        sqlite3_finalize(st);
        st = NULL;
    } else goto done;
    }
    if (prepared) {
        rc = nc_tx_prepare_package(ctx, pkg, prepared);
        goto done;
    }
    if (jmx_uci_commit(ctx, "dhcp") != UCI_OK) goto done;
    committed = 1;
    if (nc_dnsmasq_restart("/tmp/dw-dns-service-apply.log") != 0) goto done;
    if (enabled && !nc_dns_runtime_ready(port, 1)) goto done;
    rc = 0;
done:
    if (rc != 0) {
        if (!prepared) nc_restore_config("dhcp", bak_dhcp);
        if (committed)
            (void)nc_dnsmasq_restart("/tmp/dw-dns-service-rollback.log");
        nc_dns_apply_state_set("failed", "dnsmasq_restart_or_listener_readback_failed");
    } else {
        char degraded_reason[160] = "";
        int degraded = nc_dns_config_degraded_reason(degraded_reason,
                                                       sizeof(degraded_reason));
        nc_dns_apply_state_set(degraded ? "degraded" : "applied",
                               degraded ? degraded_reason : "");
    }
    nc_cleanup_backup(bak_dhcp);
    if (st) sqlite3_finalize(st);
    if (ctx) uci_free_context(ctx);
    return rc;
}

int jmx_dns_service_apply(void)
{
    return nc_dns_service_apply_scoped(NULL, NULL);
}
