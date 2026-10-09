// SPDX-License-Identifier: GPL-2.0-or-later
/* Included by jmx_netconfig_db.c: reuse the canonical setters and UCI executors. */
#include "../safeops/network_snapshot.h"
#include "../safeops/config_snapshot_codec.h"
#include "../safeops/revision_sequence.h"

#define NC_TX_EXECUTOR "netconfig_guarded_v1"
#ifndef NC_TX_APP_DB
#define NC_TX_APP_DB "/etc/dreamingwrt/apid.db"
#endif
#ifndef NC_TX_CONFIG_DIR
#define NC_TX_CONFIG_DIR "/etc/config"
#endif

static const char *const nc_tx_packages[] = {"network", "dhcp", "firewall"};

static struct json_object *nc_tx_error(const char *error, int code)
{
    struct json_object *out = json_object_new_object();
    json_object_object_add(out, "ok", json_object_new_boolean(0));
    json_object_object_add(out, "code", json_object_new_int(code));
    json_object_object_add(out, "error", json_object_new_string(error));
    json_object_object_add(out, "persisted", json_object_new_boolean(0));
    json_object_object_add(out, "applied", json_object_new_boolean(0));
    return out;
}

static int nc_tx_digest(struct json_object *value, char digest[72])
{
    const char *text = json_object_to_json_string_ext(value, JSON_C_TO_STRING_PLAIN);
    unsigned char bytes[32];
    unsigned int len = 0;
    int i;
    if (!value || !text ||
        EVP_Digest(text, strlen(text), bytes, &len, EVP_sha256(), NULL) != 1 || len != 32)
        return -1;
    memcpy(digest, "sha256:", 7);
    for (i = 0; i < 32; i++) snprintf(digest + 7 + i * 2, 3, "%02x", bytes[i]);
    return 0;
}

#include "041_nc_iptv_input.c"

static struct json_object *nc_tx_snapshot(const char *domain, const char *id)
{
    struct json_object *out = json_object_new_object();
    struct json_object *rows = safeops_network_rows(g_netconfig_db, domain, id);
    struct json_object *files = json_object_new_object();
    size_t i;
    json_object_object_add(out, "rows", rows);
    json_object_object_add(out, "files", files);
    json_object_object_add(out, "domain", json_object_new_string(domain));
    json_object_object_add(out, "id", json_object_new_string(id));
    if (!rows) goto fail;
    if (!strcmp(domain, "iptv")) {
        struct json_object *dependencies = nc_iptv_dependencies(id);
        if (!dependencies) goto fail;
        json_object_object_add(out, "dependencies", dependencies);
    }
    for (i = 0; i < sizeof(nc_tx_packages) / sizeof(nc_tx_packages[0]); i++) {
        unsigned char *bytes = NULL;
        size_t size = 0;
        char path[PATH_MAX];
        snprintf(path, sizeof(path), "%s/%s", NC_TX_CONFIG_DIR, nc_tx_packages[i]);
        if (dwnetsnap_read_file(path, &bytes, &size) != 0 || size > INT_MAX) {
            free(bytes);
            goto fail;
        }
        json_object_object_add(files, nc_tx_packages[i],
                               json_object_new_string_len((char *)bytes, (int)size));
        if (bytes) OPENSSL_cleanse(bytes, size);
        free(bytes);
    }
    return out;
fail:
    json_object_put(out);
    return NULL;
}

static int nc_tx_supported(struct json_object *config, const char *domain);

static struct json_object *nc_tx_dns_canonical(const char *id, int *supported)
{
    struct json_object *rows = safeops_network_rows(g_netconfig_db, "dns", id);
    struct json_object *parents = NULL, *config = NULL, *items = NULL;
    struct json_object *interfaces = json_object_new_array();
    size_t n;
    if (!rows || !json_object_object_get_ex(rows, "dns_service", &parents)) goto done;
    config = json_object_get(json_object_array_get_idx(parents, 0));
    json_object_object_get_ex(rows, "dns_listen_interface", &items);
    for (n = 0; n < json_object_array_length(items); n++)
        json_object_array_add(interfaces, json_object_new_string(
            nc_json_str(json_object_array_get_idx(items, n), "lan_id", "")));
    json_object_object_add(config, "listen_interfaces", json_object_get(interfaces));
    json_object_object_get_ex(rows, "dns_upstream", &items);
    json_object_object_add(config, "upstreams", json_object_get(items));
    json_object_object_get_ex(rows, "dns_rule", &items);
    json_object_object_add(config, "rules", json_object_get(items));
    *supported = !strcmp(nc_json_str(config, "mode", ""), "proxy");
done:
    json_object_put(interfaces);
    if (rows) json_object_put(rows);
    return config;
}

static struct json_object *nc_tx_canonical(const char *domain, const char *id, int *supported)
{
    if (!strcmp(domain, "dns")) return nc_tx_dns_canonical(id, supported);
    if (!strcmp(domain, "dhcp")) {
        struct json_object *config = nc_dhcp_base_get(id);
        struct json_object *dns = config ? json_object_object_get(config, "dns") : NULL;
        *supported = config && dns && json_object_array_length(dns) <= 2;
        return config;
    }
    struct json_object *response = !strcmp(domain, "wan") ?
        jmx_netconfig_wan_get(id) : jmx_netconfig_lan_get(id);
    struct json_object *data = NULL, *value = NULL;
    struct json_object *rows = safeops_network_rows(g_netconfig_db, domain, id);
    struct json_object *parents = NULL;
    if (response && rows && json_object_object_get_ex(response, "data", &data) &&
        json_object_object_get_ex(data, domain, &value) &&
        json_object_object_get_ex(rows, domain, &parents)) {
        struct json_object *parent = json_object_array_get_idx(parents, 0);
        value = json_object_get(value);
        /* Replace runtime/effective scalar projections with their stored values. */
        json_object_object_foreach(parent, key, v) {
            if (!strcmp(key, "password_ref") || !strcmp(key, "pppoe_multi_json")) continue;
            json_object_object_add(value, key, json_object_get(v));
        }
        {
            struct json_object *addresses = NULL;
            if (json_object_object_get_ex(rows, !strcmp(domain, "wan") ? "wan_address" : "lan_address", &addresses))
                json_object_object_add(value, "addresses", json_object_get(addresses));
        }
        *supported = nc_tx_supported(value, domain);
        json_object_object_del(value, "pppoe_multi");
        json_object_object_del(value, "hybrid_lines");
        json_object_object_del(value, "password_ref");
        json_object_object_del(value, "password");
        if (!strcmp(domain, "lan"))
            json_object_object_add(value, "parent", json_object_new_string(
                nc_json_str(value, "parent_lan_id", "")));
    } else value = NULL;
    if (rows) json_object_put(rows);
    if (response) json_object_put(response);
    return value;
}

static int nc_tx_supported(struct json_object *config, const char *domain)
{
    if (!config) return 0;
    if (!strcmp(domain, "wan")) {
        const char *mode = nc_json_str(config, "access_mode", "");
        struct json_object *bond = NULL;
        if (strcmp(mode, "dhcp") && strcmp(mode, "static") && strcmp(mode, "pppoe")) return 0;
        if (json_object_object_get_ex(config, "bond", &bond) &&
            nc_json_bool(bond, "enabled", 0)) return 0;
        if (json_object_object_get_ex(config, "pppoe_multi", &bond) &&
            nc_json_bool(bond, "enabled", 0)) return 0;
        if (json_object_object_get_ex(config, "hybrid_lines", &bond) &&
            json_object_is_type(bond, json_type_array) && json_object_array_length(bond)) return 0;
    }
    return 1;
}

static struct json_object *nc_tx_get(struct json_object *req)
{
    const char *domain = nc_json_str(req, "domain", "");
    const char *id = nc_json_str(req, "id", "");
    struct json_object *out, *snapshot, *config;
    char revision[72];
    int supported = 0;
    if (!safeops_network_tables(domain) || !nc_uci_section_name_ok(id))
        return nc_tx_error("invalid_network_resource", 400);
    snapshot = nc_tx_snapshot(domain, id);
    config = !strcmp(domain, "iptv") ? nc_iptv_canonical(id, &supported) :
        nc_tx_canonical(domain, id, &supported);
    if (!snapshot || !config || nc_tx_digest(snapshot, revision) != 0) {
        if (snapshot) json_object_put(snapshot);
        if (config) json_object_put(config);
        return nc_tx_error("canonical_unavailable", 503);
    }
    json_object_put(snapshot);
    out = json_object_new_object();
    json_object_object_add(out, "ok", json_object_new_boolean(1));
    json_object_object_add(out, "domain", json_object_new_string(domain));
    json_object_object_add(out, "id", json_object_new_string(id));
    json_object_object_add(out, "revision", json_object_new_string(revision));
    json_object_object_add(out, "config", config);
    json_object_object_add(out, "write_supported", json_object_new_boolean(supported));
    json_object_object_add(out, "apply_executor", json_object_new_string(NC_TX_EXECUTOR));
    if (!strcmp(domain, "iptv")) {
        struct json_object *ports = nc_iptv_query("SELECT name,label,kind,owner_type,owner_id FROM physical_port ORDER BY name");
        json_object_object_add(out, "ports", ports);
        json_object_object_add(out, "channel_references", nc_iptv_references(id));
        json_object_object_add(out, "runtime", nc_iptv_runtime(id));
    }
    return out;
}

static struct json_object *nc_tx_validate(struct json_object *req,
                                          struct json_object **merged)
{
    if (!strcmp(nc_json_str(req, "domain", ""), "iptv")) return nc_iptv_validate(req, merged);
    const char *domain = nc_json_str(req, "domain", "");
    struct json_object *out = nc_tx_get(req);
    struct json_object *config = NULL, *patch = NULL, *errors = NULL;
    const char *revision = nc_json_str(out, "revision", "");
    static const char *const wan_fields[] = {
        "name", "note", "enabled", "gateway", "mtu", "metric", "addresses", "dns", NULL
    };
    static const char *const lan_fields[] = {
        "name", "note", "enabled", "addresses", NULL
    };
    static const char *const dns_fields[] = {
        "enabled", "listen_port", "cache_enabled", "cache_size", "local_domain",
        "rebind_protection", "listen_interfaces", "upstreams", NULL
    };
    static const char *const dhcp_fields[] = {
        "enabled", "pool_start", "pool_end", "lease_minutes", "gateway", "dns1", "dns2", NULL
    };
    const char *const *fields = !strcmp(domain, "wan") ? wan_fields :
        !strcmp(domain, "dns") ? dns_fields : !strcmp(domain, "dhcp") ? dhcp_fields : lan_fields;
    if (merged) *merged = NULL;
    if (!nc_json_bool(out, "ok", 0)) return out;
    if (!nc_json_bool(out, "write_supported", 0)) {
        json_object_object_add(out, "error", json_object_new_string("network_mode_not_supported"));
        json_object_object_add(out, "code", json_object_new_int(501));
        goto invalid;
    }
    if (!nc_json_str(req, "if_revision", "")[0] ||
        strcmp(nc_json_str(req, "if_revision", ""), revision)) {
        json_object_object_add(out, "error", json_object_new_string(
            nc_json_str(req, "if_revision", "")[0] ? "revision_conflict" : "revision_required"));
        json_object_object_add(out, "code", json_object_new_int(
            nc_json_str(req, "if_revision", "")[0] ? 409 : 428));
        goto invalid;
    }
    if (!json_object_object_get_ex(req, "config", &patch) ||
        !json_object_is_type(patch, json_type_object) || json_object_object_length(patch) == 0) {
        json_object_object_add(out, "error", json_object_new_string("config_patch_required"));
        json_object_object_add(out, "code", json_object_new_int(400));
        goto invalid;
    }
    json_object_object_get_ex(out, "config", &config);
    config = json_tokener_parse(json_object_to_json_string_ext(config, JSON_C_TO_STRING_PLAIN));
    errors = json_object_new_array();
    json_object_object_foreach(patch, key, value) {
        size_t i;
        for (i = 0; fields[i] && strcmp(fields[i], key); i++) {}
        if (!fields[i]) {
            nc_add_field_error(errors, key, "unsupported_field", "Field is not writable in this transaction");
            continue;
        }
        if (!value) {
            nc_add_field_error(errors, key, "invalid_type", "Null is not a configuration value");
            continue;
        }
        if (!strcmp(domain, "dhcp")) {
            enum json_type type = !strcmp(key, "enabled") ? json_type_boolean :
                !strcmp(key, "lease_minutes") ? json_type_int : json_type_string;
            if (!json_object_is_type(value, type))
                nc_add_field_error(errors, key, "invalid_type", "Invalid DHCP field type");
            else json_object_object_add(config, key, json_object_get(value));
            continue;
        }
        if (!strcmp(domain, "dns")) {
            enum json_type type = !strcmp(key, "enabled") || !strcmp(key, "cache_enabled") ||
                !strcmp(key, "rebind_protection") ? json_type_boolean :
                !strcmp(key, "listen_port") || !strcmp(key, "cache_size") ? json_type_int :
                !strcmp(key, "listen_interfaces") || !strcmp(key, "upstreams") ? json_type_array :
                json_type_string;
            if (!json_object_is_type(value, type)) {
                nc_add_field_error(errors, key, "invalid_type", "Invalid DNS field type");
                continue;
            }
            if (!strcmp(key, "upstreams")) {
                struct json_object *stored = NULL;
                json_object_object_get_ex(config, "upstreams", &stored);
                for (size_t n = 0; n < json_object_array_length(value); n++) {
                    struct json_object *row = json_object_array_get_idx(value, n);
                    int unchanged = 0;
                    if (!strcmp(nc_json_str(row, "protocol", "udp"), "udp")) continue;
                    for (size_t j = 0; stored && j < json_object_array_length(stored); j++)
                        if (json_object_equal(row, json_object_array_get_idx(stored, j))) unchanged = 1;
                    /* dnsmasq server= does not select a per-upstream TCP transport. */
                    if (!unchanged)
                        nc_add_field_error(errors, key, "transport_not_supported",
                            "Only default DNS upstream transport is writable");
                }
            }
            json_object_object_add(config, key, json_object_get(value));
            continue;
        }
        if (!strcmp(key, "enabled") && !json_object_is_type(value, json_type_boolean)) {
            nc_add_field_error(errors, key, "invalid_type", "Boolean required");
            continue;
        }
        if ((!strcmp(key, "mtu") || !strcmp(key, "metric")) &&
            !json_object_is_type(value, json_type_int)) {
            nc_add_field_error(errors, key, "invalid_type", "Integer required");
            continue;
        }
        if (!strcmp(key, "addresses") && !json_object_is_type(value, json_type_array)) {
            nc_add_field_error(errors, key, "invalid_type", "Structured configuration required");
            continue;
        }
        if (strcmp(key, "enabled") &&
            strcmp(key, "mtu") && strcmp(key, "metric") && strcmp(key, "addresses") &&
            strcmp(key, "dns") && !json_object_is_type(value, json_type_string)) {
            nc_add_field_error(errors, key, "invalid_type", "String required");
            continue;
        }
        if (!strcmp(key, "mtu") && !strcmp(nc_json_str(config, "access_mode", ""), "pppoe"))
            nc_add_field_error(errors, key, "unsupported_field", "PPPoE MTU is managed by the PPP executor");
        if (!strcmp(key, "addresses")) {
            size_t n;
            int primary = 0;
            if (!strcmp(domain, "wan") && strcmp(nc_json_str(config, "access_mode", ""), "static"))
                nc_add_field_error(errors, key, "unsupported_field", "Only static WAN has configured addresses");
            for (n = 0; n < json_object_array_length(value); n++) {
                struct json_object *row = json_object_array_get_idx(value, n), *ip = NULL, *prefix = NULL;
                if (!row || !json_object_is_type(row, json_type_object) ||
                    !json_object_object_get_ex(row, "ip", &ip) || !json_object_is_type(ip, json_type_string) ||
                    !nc_is_valid_ip(json_object_get_string(ip)) ||
                    !json_object_object_get_ex(row, "prefix", &prefix) ||
                    !json_object_is_type(prefix, json_type_int) ||
                    json_object_get_int(prefix) < 1 || json_object_get_int(prefix) > 30) {
                    nc_add_field_error(errors, key, "invalid_address", "IPv4 address and integer prefix 1-30 required");
                    continue;
                }
                primary += nc_json_bool(row, "primary", nc_json_bool(row, "is_primary", 0)) != 0;
            }
            if (primary != 1)
                nc_add_field_error(errors, key, "invalid_primary", "Exactly one primary address is required");
        }
        json_object_object_add(config, key, json_object_get(value));
        if (!strcmp(key, "dns")) {
            if (!json_object_is_type(value, json_type_array))
                nc_add_field_error(errors, key, "invalid_type", "DNS must be an array");
            else {
                size_t n;
                for (n = 0; n < json_object_array_length(value); n++)
                    if (!json_object_is_type(json_object_array_get_idx(value, n), json_type_string) ||
                        !nc_is_valid_ip(json_object_get_string(json_object_array_get_idx(value, n))))
                        nc_add_field_error(errors, key, "invalid_ip", "DNS must contain IP addresses");
                json_object_object_add(config, "dns_json", json_object_new_string(
                    json_object_to_json_string_ext(value, JSON_C_TO_STRING_PLAIN)));
            }
        }
    }
    if (!strcmp(domain, "dhcp")) {
        char error[128] = "";
        if (nc_dhcp_base_validate(config, error, sizeof(error)) != 0)
            nc_add_field_error(errors, "dhcp", error, "DHCP configuration is invalid");
    } else if (!strcmp(domain, "dns")) {
        int rc = nc_dns_service_validate(config, 1);
        if (rc)
            nc_add_field_error(errors, "dns", "invalid_dns_config",
                rc == -3 || rc == -4 ? "DNS capability is not supported" :
                rc == -8 ? "Enabled DNS requires valid LAN listeners" : "DNS configuration is invalid");
    } else {
        struct json_object *domain_errors = !strcmp(domain, "wan") ?
            jmx_netconfig_wan_validate(config) : jmx_netconfig_lan_validate(config);
        size_t i;
        for (i = 0; domain_errors && i < json_object_array_length(domain_errors); i++)
            json_object_array_add(errors, json_object_get(json_object_array_get_idx(domain_errors, i)));
        if (domain_errors) json_object_put(domain_errors);
    }
    if (!nc_tx_supported(config, domain))
        nc_add_field_error(errors, "access_mode", "not_supported", "Network mode is not supported");
    json_object_object_add(out, "errors", errors);
    if (json_object_array_length(errors)) {
        json_object_put(config);
        json_object_object_add(out, "error", json_object_new_string("validation_failed"));
        json_object_object_add(out, "code", json_object_new_int(400));
        goto invalid;
    }
    /* These nested projections are not edits. Preserve their stored rows rather
     * than round-tripping aliases or rewriting the port/DHCP ownership surface. */
    if (!strcmp(domain, "lan")) {
        json_object_object_del(config, "dhcp");
        json_object_object_del(config, "ipv6");
        json_object_object_del(config, "ports");
    }
    if (merged) *merged = config;
    else json_object_put(config);
    json_object_object_add(out, "valid", json_object_new_boolean(1));
    json_object_object_add(out, "requires_confirm", json_object_new_boolean(1));
    json_object_object_add(out, "management_path_touched", json_object_new_string("unknown"));
    return out;
invalid:
    json_object_object_add(out, "ok", json_object_new_boolean(0));
    json_object_object_add(out, "valid", json_object_new_boolean(0));
    return out;
}

static sqlite3 *nc_tx_app_open(void)
{
    sqlite3 *db = NULL;
    if (sqlite3_open_v2(NC_TX_APP_DB, &db, SQLITE_OPEN_READWRITE, NULL) != SQLITE_OK) {
        if (db) sqlite3_close(db);
        return NULL;
    }
    sqlite3_busy_timeout(db, 1000);
    return db;
}

static int nc_tx_existing(sqlite3 *db, const char *key, int *replay, int *pending)
{
    sqlite3_stmt *st = NULL;
    int rc;
    /* A replay only reads an existing result. Do not require the task database's
     * writer lock while the watchdog or session bookkeeping owns it. */
    if (sqlite3_prepare_v2(db,
        "SELECT id,idempotency_key=?1 AS same_request FROM config_apply_tasks "
        "WHERE idempotency_key=?1 OR state IN ('pending','rolling_back') "
        "ORDER BY same_request DESC,id DESC LIMIT 1", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, key, -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) {
        if (sqlite3_column_int(st, 1)) *replay = sqlite3_column_int(st, 0);
        else *pending = sqlite3_column_int(st, 0);
    }
    sqlite3_finalize(st);
    return rc == SQLITE_ROW || rc == SQLITE_DONE ? 0 : -1;
}

static int nc_tx_write_files(struct json_object *files, struct json_object *unchanged)
{
    size_t i;
    for (i = 0; i < sizeof(nc_tx_packages) / sizeof(nc_tx_packages[0]); i++) {
        struct json_object *bytes = NULL, *old = NULL;
        char target[PATH_MAX], tmp[PATH_MAX];
        struct stat mode;
        int fd;
        if (!json_object_object_get_ex(files, nc_tx_packages[i], &bytes) ||
            !json_object_is_type(bytes, json_type_string)) return -1;
        if (unchanged && json_object_object_get_ex(unchanged, nc_tx_packages[i], &old) &&
            json_object_equal(old, bytes)) continue;
        snprintf(target, sizeof(target), "%s/%s", NC_TX_CONFIG_DIR, nc_tx_packages[i]);
        snprintf(tmp, sizeof(tmp), "%s/.%s-nettx-XXXXXX", NC_TX_CONFIG_DIR, nc_tx_packages[i]);
        if (stat(target, &mode) != 0) return -1;
        fd = mkstemp(tmp);
        if (fd < 0) return -1;
        close(fd);
        if (dwnetsnap_write_file(tmp, (const unsigned char *)json_object_get_string(bytes),
                                 json_object_get_string_len(bytes)) != 0 ||
            chmod(tmp, mode.st_mode & 0777) != 0 ||
            rename(tmp, target) != 0) {
            unlink(tmp);
            return -1;
        }
    }
    return 0;
}

/* SQLite rows commit together; each UCI file is replaced atomically. Only these
 * recorded before/after components can be the result of an interrupted writer. */
static int nc_tx_recovery_matches(struct json_object *before, struct json_object *prepared,
                                   struct json_object *current)
{
    struct json_object *b = NULL, *p = NULL, *c = NULL;
    struct json_object *bf = NULL, *pf = NULL, *cf = NULL;
    if (before && !strcmp(nc_json_str(before, "domain", ""), "iptv")) {
        struct json_object *bd = json_object_object_get(before, "dependencies");
        struct json_object *pd = json_object_object_get(prepared, "dependencies");
        struct json_object *cd = json_object_object_get(current, "dependencies");
        if (!bd || !pd || !cd || (!json_object_equal(cd, bd) && !json_object_equal(cd, pd))) return 0;
    }
    if (!before || !prepared || !current ||
        !json_object_object_get_ex(before, "rows", &b) ||
        !json_object_object_get_ex(prepared, "rows", &p) ||
        !json_object_object_get_ex(current, "rows", &c) ||
        (!json_object_equal(c, b) && !json_object_equal(c, p)) ||
        !json_object_object_get_ex(before, "files", &bf) ||
        !json_object_object_get_ex(prepared, "files", &pf) ||
        !json_object_object_get_ex(current, "files", &cf)) return 0;
    for (size_t i = 0; i < sizeof(nc_tx_packages) / sizeof(nc_tx_packages[0]); i++) {
        if (!json_object_object_get_ex(bf, nc_tx_packages[i], &b) ||
            !json_object_object_get_ex(pf, nc_tx_packages[i], &p) ||
            !json_object_object_get_ex(cf, nc_tx_packages[i], &c) ||
            (!json_object_equal(c, b) && !json_object_equal(c, p))) return 0;
    }
    return 1;
}

static int nc_tx_journal_put(struct ac_secrets *vault, const char *secret_id,
                              struct json_object *before, struct json_object *prepared,
                              int restoring)
{
    struct json_object *journal = json_object_new_object();
    const char *text;
    int rc;
    json_object_object_add(journal, "before", json_object_get(before));
    json_object_object_add(journal, "prepared", json_object_get(prepared));
    json_object_object_add(journal, "restoring", json_object_new_boolean(restoring));
    text = json_object_to_json_string_ext(journal, JSON_C_TO_STRING_PLAIN);
    rc = ac_secrets_put(vault, secret_id, 1, (const unsigned char *)text, strlen(text));
    json_object_put(journal);
    return rc == AC_SECRETS_OK ? 0 : -1;
}

static int nc_tx_lock_pending(sqlite3 *app, int task_id)
{
    sqlite3_stmt *st = NULL;
    int rc = SQLITE_ERROR;
    if (sqlite3_exec(app, "BEGIN IMMEDIATE", NULL, NULL, NULL) != SQLITE_OK) return -1;
    if (sqlite3_prepare_v2(app, "SELECT 1 FROM config_apply_tasks WHERE id=?1 AND state='pending' "
                               "AND rollback_deadline>?2", -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_int(st, 1, task_id);
        sqlite3_bind_int64(st, 2, nc_now_s());
        rc = sqlite3_step(st);
    }
    sqlite3_finalize(st);
    if (rc == SQLITE_ROW) return 0;
    sqlite3_exec(app, "ROLLBACK", NULL, NULL, NULL);
    return -1;
}

static int nc_tx_restore_snapshot(struct json_object *snapshot)
{
    struct json_object *rows = NULL, *files = NULL;
    const char *domain = nc_json_str(snapshot, "domain", "");
    const char *id = nc_json_str(snapshot, "id", "");
    if (!json_object_object_get_ex(snapshot, "rows", &rows) ||
        !json_object_object_get_ex(snapshot, "files", &files) ||
        (sqlite3_get_autocommit(g_netconfig_db) && nc_exec("BEGIN IMMEDIATE") != 0))
        return -1;
    if (safeops_network_restore_rows(g_netconfig_db, domain, id, rows) != 0 ||
        nc_tx_write_files(files, NULL) != 0) goto fail;
    if (nc_exec("COMMIT") != 0) goto fail;
    if (!strcmp(domain, "dhcp"))
        return nc_dnsmasq_restart("/tmp/dw-dhcp-transaction-rollback.log");
    if (!strcmp(domain, "dns")) {
        struct json_object *services = NULL;
        struct json_object *service;
        json_object_object_get_ex(rows, "dns_service", &services);
        service = json_object_array_get_idx(services, 0);
        if (nc_dnsmasq_restart("/tmp/dw-dns-transaction-rollback.log") != 0) return -1;
        return !nc_json_bool(service, "enabled", 0) ||
            nc_dns_runtime_ready(nc_json_int(service, "listen_port", 53), 1) ? 0 : -1;
    }
    return nc_reload_network_stack(1, 1, "/tmp/dw-network-transaction-rollback.log");
fail:
    nc_exec("ROLLBACK");
    return -1;
}

static int nc_tx_store_evidence(sqlite3 *db, int id, const char *state,
                                 const char *digest, struct json_object *readback,
                                 const char *error, int rolled_back)
{
    sqlite3_stmt *st = NULL;
    int rc;
    if (sqlite3_prepare_v2(db,
        "UPDATE config_apply_tasks SET state=?1,applied_digest=?2,target_digest=?2,"
        "readback_json=?3,error=?4,rollback_applied=?5,rollback_error=?6,"
        "finished_at=?7 WHERE id=?8", -1, &st, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_text(st, 1, state, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, digest ? digest : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, readback ? json_object_to_json_string_ext(readback, JSON_C_TO_STRING_PLAIN) : "[]",
                       -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 4, error ? error : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 5, rolled_back);
    sqlite3_bind_text(st, 6, !strcmp(state, "rollback_failed") ? "network_restore_failed" : "",
                       -1, SQLITE_STATIC);
    sqlite3_bind_int64(st, 7, !strcmp(state, "pending") ? 0 : nc_now_s());
    sqlite3_bind_int(st, 8, id);
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

static struct json_object *nc_tx_apply(struct json_object *req)
{
    const char *domain = nc_json_str(req, "domain", "");
    const char *id = nc_json_str(req, "id", "");
    const char *key = nc_json_str(req, "idempotency_key", "");
    struct json_object *out = NULL, *merged = NULL, *snapshot = NULL, *after = NULL;
    struct json_object *readback = NULL, *reference = NULL, *prepared_files = NULL, *prepared = NULL;
    sqlite3 *app = NULL;
    sqlite3_stmt *st = NULL;
    struct ac_secrets *vault = NULL;
    char secret_id[96], revision[72], after_digest[72] = "";
    int replay = 0, pending = 0, task_id = 0, config_tx = 0, app_tx = 0, task_persisted = 0;
    int64_t sequence = 0, now = nc_now_s();
    int timeout = nc_json_int(req, "rollback_timeout", 90), rc;
    const char *error = "transaction_unavailable";

    if (!key[0] || strlen(key) > 128) return nc_tx_error("idempotency_key_required", 400);
    if (!nc_json_bool(req, "confirm_risk", 0)) return nc_tx_error("confirmation_required", 409);
    if (timeout < 60 || timeout > 3600) return nc_tx_error("invalid_rollback_timeout", 400);
    app = nc_tx_app_open();
    if (!app) goto fail;
    if (nc_tx_existing(app, key, &replay, &pending) != 0) goto fail;
    rc = replay > 0 ? SAFEOPS_REVISION_REPLAY : pending > 0 ? SAFEOPS_REVISION_ACTIVE :
        safeops_revision_begin(app, key, &replay, &pending, &sequence);
    if (rc == SAFEOPS_REVISION_REPLAY || rc == SAFEOPS_REVISION_ACTIVE) {
        out = nc_tx_error(rc == SAFEOPS_REVISION_REPLAY ? "" : "transaction_pending", 409);
        json_object_object_add(out, "ok", json_object_new_boolean(rc == SAFEOPS_REVISION_REPLAY));
        json_object_object_add(out, "idempotent_replay", json_object_new_boolean(rc == SAFEOPS_REVISION_REPLAY));
        json_object_object_add(out, "task_id", json_object_new_int(
            rc == SAFEOPS_REVISION_REPLAY ? replay : pending));
        if (rc == SAFEOPS_REVISION_REPLAY) {
            json_object_object_del(out, "code");
            json_object_object_del(out, "error");
        }
        goto done;
    }
    if (rc == SAFEOPS_REVISION_ERROR) goto fail;
    app_tx = 1;
    if (jmx_netconfig_db_init() != 0 || nc_exec("BEGIN IMMEDIATE") != 0) goto fail;
    config_tx = 1;
    out = nc_tx_validate(req, &merged);
    if (!nc_json_bool(out, "valid", 0)) goto done;
    snapshot = nc_tx_snapshot(domain, id);
    if (!snapshot || nc_tx_digest(snapshot, revision) != 0) goto fail;
    if (ac_secrets_schema_init(app) != AC_SECRETS_OK ||
        ac_secrets_open_or_create(app, DWNETSNAP_VAULT_KEY_PATH, &vault) != AC_SECRETS_OK)
        goto fail;
    reference = json_object_new_object();
    json_object_object_add(reference, "domain", json_object_new_string(domain));
    json_object_object_add(reference, "id", json_object_new_string(id));
    if (sqlite3_prepare_v2(app,
        "INSERT INTO config_apply_tasks(scope,changes_json,state,rollback_timeout,started_at,"
        "snapshot_path,snapshot_at,snapshot_ok,apply_executor,config_revision,before_digest,"
        "idempotency_key,rollback_deadline,changed_paths_json,preflight_json) "
        "VALUES('network',?1,'pending',?2,?3,'',?3,1,?4,?5,?6,?7,?8,?9,?10)",
        -1, &st, NULL) != SQLITE_OK) goto fail;
    sqlite3_bind_text(st, 1, json_object_to_json_string_ext(reference, JSON_C_TO_STRING_PLAIN), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 2, timeout);
    sqlite3_bind_int64(st, 3, now);
    sqlite3_bind_text(st, 4, NC_TX_EXECUTOR, -1, SQLITE_STATIC);
    sqlite3_bind_int64(st, 5, sequence);
    sqlite3_bind_text(st, 6, revision, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 7, key, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 8, now + timeout);
    sqlite3_bind_text(st, 9, !strcmp(domain, "iptv") ? "[\"iptv_input\"]" : !strcmp(domain, "wan") ? "[\"wan\"]" :
        !strcmp(domain, "dns") ? "[\"dns\"]" : !strcmp(domain, "dhcp") ? "[\"dhcp\"]" : "[\"lan\"]", -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 10, !strcmp(domain, "iptv") ?
        "{\"management_path_touched\":\"no\",\"risk_confirmed\":true,\"dedicated_input\":true}" :
        "{\"management_path_touched\":\"unknown\",\"risk_confirmed\":true}", -1, SQLITE_STATIC);
    rc = sqlite3_step(st);
    sqlite3_finalize(st); st = NULL;
    if (rc != SQLITE_DONE) goto fail;
    task_id = (int)sqlite3_last_insert_rowid(app);
    snprintf(secret_id, sizeof(secret_id), "network-transaction-%d", task_id);
    {
        const char *text = json_object_to_json_string_ext(snapshot, JSON_C_TO_STRING_PLAIN);
        if (ac_secrets_put(vault, secret_id, 1, (const unsigned char *)text, strlen(text)) != AC_SECRETS_OK)
            goto fail;
    }
    if (sqlite3_prepare_v2(app, "UPDATE config_apply_tasks SET snapshot_path=?1 WHERE id=?2",
                           -1, &st, NULL) != SQLITE_OK) goto fail;
    sqlite3_bind_text(st, 1, secret_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 2, task_id);
    rc = sqlite3_step(st);
    sqlite3_finalize(st); st = NULL;
    if (rc != SQLITE_DONE || sqlite3_exec(app, "COMMIT", NULL, NULL, NULL) != SQLITE_OK) goto fail;
    task_persisted = 1;
    app_tx = 0;
    /* Prepare with the existing setters/renderers, but do not publish UCI or
     * reload services until the complete recovery journal is durable. */
    if (nc_tx_lock_pending(app, task_id) != 0) goto fail;
    app_tx = 1;
    prepared_files = json_object_new_object();
    if (!strcmp(domain, "iptv")) {
        rc = nc_iptv_prepare(merged, nc_json_str(req, "operation", "update"), prepared_files);
    } else if (!strcmp(domain, "dhcp")) {
        struct json_object *patch = json_object_object_get(req, "config");
        rc = nc_dhcp_base_set(merged);
        if (!rc) rc = nc_dhcp_apply_scoped(id, patch, prepared_files);
    } else if (!strcmp(domain, "dns")) {
        struct json_object *patch = NULL;
        json_object_object_get_ex(req, "config", &patch);
        rc = jmx_dns_service_set(merged);
        if (rc == 0) rc = nc_dns_service_apply_scoped(patch, prepared_files);
    } else {
        rc = !strcmp(domain, "wan") ? jmx_netconfig_wan_set(merged) : jmx_netconfig_lan_set(merged);
        if (rc == 0) rc = !strcmp(domain, "wan") ?
            nc_apply_wan_scoped(id, prepared_files) : nc_apply_lan_scoped(id, 0, prepared_files);
    }
    if (rc != 0) {
        /* Preparation failed without changing files or runtime. */
        nc_exec("ROLLBACK");
        config_tx = 0;
        nc_tx_store_evidence(app, task_id, "rolled_back", "", NULL, "network_apply_failed", 1);
        sqlite3_exec(app, "COMMIT", NULL, NULL, NULL);
        app_tx = 0;
        error = "network_apply_failed";
        goto fail;
    }
    prepared = nc_tx_snapshot(domain, id);
    {
        struct json_object *files = prepared ? json_object_object_get(prepared, "files") : NULL;
        struct json_object *original = json_object_object_get(snapshot, "files");
        if (!files || !json_object_equal(files, original)) {
            error = "stale_watchdog_digest_mismatch";
            goto preparation_failed;
        }
        json_object_object_foreach(prepared_files, name, bytes) {
            json_object_object_add(files, name, json_object_get(bytes));
        }
    }
    if (nc_tx_journal_put(vault, secret_id, snapshot, prepared, 0) != 0 ||
        sqlite3_exec(app, "COMMIT", NULL, NULL, NULL) != SQLITE_OK) goto fail;
    app_tx = 0;
    if (nc_tx_lock_pending(app, task_id) != 0) {
        error = "transaction_no_longer_pending";
        goto fail;
    }
    app_tx = 1;
    {
        struct json_object *current = nc_tx_snapshot(domain, id);
        rc = current && json_object_equal(json_object_object_get(current, "files"),
                                           json_object_object_get(snapshot, "files")) ? 0 : -1;
        if (current) json_object_put(current);
    }
    if (!rc) rc = nc_tx_write_files(json_object_object_get(prepared, "files"),
                                     json_object_object_get(snapshot, "files"));
    if (!rc && (!strcmp(domain, "dns") || !strcmp(domain, "dhcp"))) {
        rc = nc_dnsmasq_restart("/tmp/dw-network-transaction-apply.log");
        if (!rc && !strcmp(domain, "dns") && nc_json_bool(merged, "enabled", 0) &&
            !nc_dns_runtime_ready(nc_json_int(merged, "listen_port", 53), 1)) rc = -1;
    } else if (!rc) {
        rc = nc_reload_network_stack(0, !strcmp(domain, "wan") || !strcmp(domain, "iptv"),
                                     "/tmp/dw-network-transaction-apply.log");
        if (!rc && !strcmp(domain, "iptv") && !strcmp(nc_json_str(req, "operation", ""), "reconnect"))
            rc = nc_iptv_reconnect(id);
    }
    if (!rc) rc = nc_exec("COMMIT");
    if (rc != 0) {
        nc_exec("ROLLBACK");
        config_tx = 0;
        error = "network_apply_failed";
        goto restore;
    }
    config_tx = 0;
    after = nc_tx_snapshot(domain, id);
    if (!after || !json_object_equal(after, prepared) || nc_tx_digest(after, after_digest) != 0) {
        error = "readback_failed";
        goto restore;
    }
    readback = json_object_new_array();
    {
        struct json_object *entry = nc_tx_get(req);
        if (!nc_json_bool(entry, "ok", 0)) { json_object_put(entry); error = "readback_failed"; goto restore; }
        json_object_object_add(entry, "persisted", json_object_new_boolean(1));
        json_object_object_add(entry, "applied", json_object_new_boolean(1));
        json_object_object_add(entry, "runtime_reloaded", json_object_new_boolean(1));
        int dns_checked = !strcmp(domain, "dns") && nc_json_bool(merged, "enabled", 0);
        json_object_object_add(entry, "runtime_verified", json_object_new_boolean(dns_checked));
        json_object_object_add(entry, "readback_source", json_object_new_string(dns_checked ?
            "netconfig_db_uci_dnsmasq_process_local_dns_query" : "netconfig_db_and_uci_files"));
        json_object_array_add(readback, entry);
    }
    if (nc_tx_store_evidence(app, task_id, "pending", after_digest, readback, "", 0) != 0 ||
        sqlite3_exec(app, "COMMIT", NULL, NULL, NULL) != SQLITE_OK) {
        error = "task_evidence_failed";
        goto restore;
    }
    app_tx = 0;
    json_object_put(out);
    out = json_object_new_object();
    json_object_object_add(out, "ok", json_object_new_boolean(1));
    json_object_object_add(out, "task_id", json_object_new_int(task_id));
    goto done;
restore:
    {
        struct json_object *current = NULL;
        rc = -1;
        if (nc_exec("BEGIN IMMEDIATE") == 0) {
            current = nc_tx_snapshot(domain, id);
            if (nc_tx_recovery_matches(snapshot, prepared, current))
                rc = nc_tx_restore_snapshot(snapshot);
            else error = "stale_watchdog_digest_mismatch";
        }
        if (current) json_object_put(current);
    }
    nc_tx_store_evidence(app, task_id, rc == 0 ? "rolled_back" : "rollback_failed",
                          "", NULL, error, rc == 0);
    sqlite3_exec(app, "COMMIT", NULL, NULL, NULL);
    app_tx = 0;
    goto fail;
preparation_failed:
    nc_exec("ROLLBACK");
    config_tx = 0;
    nc_tx_store_evidence(app, task_id, "rollback_failed", "", NULL, error, 0);
    sqlite3_exec(app, "COMMIT", NULL, NULL, NULL);
    app_tx = 0;
fail:
    if (out) json_object_put(out);
    out = nc_tx_error(error, 500);
    if (task_persisted) {
        json_object_object_add(out, "task_id", json_object_new_int(task_id));
        json_object_object_add(out, "persisted", NULL);
        json_object_object_add(out, "applied", NULL);
    }
done:
    if (st) sqlite3_finalize(st);
    if (config_tx || (g_netconfig_db && !sqlite3_get_autocommit(g_netconfig_db))) nc_exec("ROLLBACK");
    if (app_tx) sqlite3_exec(app, "ROLLBACK", NULL, NULL, NULL);
    if (vault) ac_secrets_close(vault);
    if (app) sqlite3_close(app);
    if (reference) json_object_put(reference);
    if (snapshot) json_object_put(snapshot);
    if (after) json_object_put(after);
    if (readback) json_object_put(readback);
    if (merged) json_object_put(merged);
    if (prepared_files) json_object_put(prepared_files);
    if (prepared) json_object_put(prepared);
    return out;
}

static struct json_object *nc_tx_rollback(struct json_object *req)
{
    sqlite3 *app = nc_tx_app_open();
    sqlite3_stmt *st = NULL;
    struct ac_secrets *vault = NULL;
    struct json_object *journal = NULL, *snapshot = NULL, *prepared = NULL, *current = NULL, *out = NULL;
    unsigned char *raw = NULL;
    size_t length = 0;
    int task_id = nc_json_int(req, "task_id", 0), rc = -1, app_tx = 0;
    char secret_id[96] = "", expected[72] = "", before_digest[72] = "", actual[72];
    const char *error = "network_rollback_unavailable";
    if (!app || task_id <= 0) goto done;
    if (sqlite3_exec(app, "BEGIN IMMEDIATE", NULL, NULL, NULL) != SQLITE_OK) goto done;
    app_tx = 1;
    if (sqlite3_prepare_v2(app,
        "SELECT snapshot_path,applied_digest,before_digest "
        "FROM config_apply_tasks WHERE id=?1 "
        "AND state='rolling_back' AND apply_executor=?2", -1, &st, NULL) != SQLITE_OK) goto done;
    sqlite3_bind_int(st, 1, task_id);
    sqlite3_bind_text(st, 2, NC_TX_EXECUTOR, -1, SQLITE_STATIC);
    if (sqlite3_step(st) == SQLITE_ROW) {
        snprintf(secret_id, sizeof(secret_id), "%s", sqlite3_column_text(st, 0));
        snprintf(expected, sizeof(expected), "%s", sqlite3_column_text(st, 1));
        snprintf(before_digest, sizeof(before_digest), "%s", sqlite3_column_text(st, 2));
    }
    sqlite3_finalize(st); st = NULL;
    if (!secret_id[0] || ac_secrets_open(app, DWNETSNAP_VAULT_KEY_PATH, &vault) != AC_SECRETS_OK ||
        ac_secrets_get(vault, secret_id, 1, &raw, &length) != AC_SECRETS_OK || length > INT_MAX) goto done;
    {
        struct json_tokener *tok = json_tokener_new();
        journal = json_tokener_parse_ex(tok, (char *)raw, (int)length);
        if (json_tokener_get_error(tok) != json_tokener_success) {
            if (journal) json_object_put(journal);
            journal = NULL;
        }
        json_tokener_free(tok);
    }
    if (!journal) goto done;
    if (json_object_object_get_ex(journal, "before", &snapshot))
        json_object_object_get_ex(journal, "prepared", &prepared);
    else snapshot = journal; /* Tasks created before the recovery journal. */
    if (!snapshot) goto done;
    if (nc_exec("BEGIN IMMEDIATE") != 0) goto done;
    current = nc_tx_snapshot(nc_json_str(snapshot, "domain", ""), nc_json_str(snapshot, "id", ""));
    int recovering = prepared && (!expected[0] || nc_json_bool(journal, "restoring", 0));
    if (!current || nc_tx_digest(current, actual) != 0 ||
        (recovering ? !nc_tx_recovery_matches(snapshot, prepared, current) :
         strcmp(expected[0] ? expected : before_digest, actual))) {
        error = "stale_watchdog_digest_mismatch";
        goto done;
    }
    /* Record restore intent before the first replacement, so another process
     * can resume after this one dies without mistaking our preimage for drift. */
    if (nc_tx_journal_put(vault, secret_id, snapshot, prepared ? prepared : current, 1) != 0 ||
        sqlite3_exec(app, "COMMIT", NULL, NULL, NULL) != SQLITE_OK) goto done;
    app_tx = 0;
    rc = nc_tx_restore_snapshot(snapshot);
    if (rc != 0) error = "network_restore_failed";
done:
    if (g_netconfig_db && !sqlite3_get_autocommit(g_netconfig_db)) nc_exec("ROLLBACK");
    if (app_tx) sqlite3_exec(app, "ROLLBACK", NULL, NULL, NULL);
    out = rc == 0 ? json_object_new_object() : nc_tx_error(error, 500);
    if (rc == 0) {
        json_object_object_add(out, "ok", json_object_new_boolean(1));
        json_object_object_add(out, "rollback_applied", json_object_new_boolean(1));
    }
    if (st) sqlite3_finalize(st);
    if (raw) ac_secrets_clear(raw, length);
    if (vault) ac_secrets_close(vault);
    if (app) sqlite3_close(app);
    if (journal) json_object_put(journal);
    if (current) json_object_put(current);
    return out;
}

struct json_object *jmx_netconfig_transaction(const char *method, struct json_object *req)
{
    if (jmx_netconfig_db_init() != 0) return nc_tx_error("config_unavailable", 503);
    if (!strcmp(method, "network_transaction_get")) return nc_tx_get(req);
    if (!strcmp(method, "network_transaction_validate")) return nc_tx_validate(req, NULL);
    if (!strcmp(method, "network_transaction_apply")) return nc_tx_apply(req);
    if (!strcmp(method, "network_transaction_rollback")) return nc_tx_rollback(req);
    return nc_tx_error("not_supported", 501);
}

#ifndef NC_IPTV_PLATFORM_FIXTURE
#include "042_nc_iptv_apply.c"
#endif
