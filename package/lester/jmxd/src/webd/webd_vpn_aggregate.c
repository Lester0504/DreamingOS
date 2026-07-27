// SPDX-License-Identifier: GPL-2.0-or-later
#include "webd_vpn_aggregate.h"

#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define VPN_SYS_CLASS_NET "/sys/class/net"

static struct json_object *vpn_child(struct json_object *obj, const char *key)
{
    struct json_object *value = NULL;

    if (!obj || !key || !json_object_object_get_ex(obj, key, &value))
        return NULL;
    return value;
}

static struct json_object *vpn_child_object(struct json_object *obj, const char *key)
{
    struct json_object *value = vpn_child(obj, key);

    return value && json_object_is_type(value, json_type_object) ? value : NULL;
}

static struct json_object *vpn_child_array(struct json_object *obj, const char *key)
{
    struct json_object *value = vpn_child(obj, key);

    return value && json_object_is_type(value, json_type_array) ? value : NULL;
}

static const char *vpn_string(struct json_object *obj, const char *key)
{
    struct json_object *value = vpn_child(obj, key);
    const char *text;

    if (!value || !json_object_is_type(value, json_type_string))
        return "";
    text = json_object_get_string(value);
    return text ? text : "";
}

static int vpn_boolean(struct json_object *obj, const char *key, int fallback)
{
    struct json_object *value = vpn_child(obj, key);

    return value ? json_object_get_boolean(value) : fallback;
}

static void vpn_add_null(struct json_object *obj, const char *key)
{
    json_object_object_add(obj, key, NULL);
}

static void vpn_add_string(struct json_object *obj, const char *key, const char *value)
{
    json_object_object_add(obj, key, json_object_new_string(value ? value : ""));
}

static void vpn_copy(struct json_object *dst, struct json_object *src, const char *key)
{
    struct json_object *value = vpn_child(src, key);

    if (value)
        json_object_object_add(dst, key, json_object_get(value));
}

static int vpn_safe_ifname(const char *name)
{
    size_t i;

    if (!name || !name[0] || strlen(name) >= 64)
        return 0;
    for (i = 0; name[i]; i++) {
        unsigned char ch = (unsigned char)name[i];

        if (!isalnum(ch) && ch != '_' && ch != '-' && ch != '.' && ch != ':')
            return 0;
    }
    return 1;
}

static int vpn_read_line(const char *path, char *out, size_t out_len)
{
    FILE *stream;

    if (!path || !out || out_len < 2)
        return -1;
    out[0] = '\0';
    stream = fopen(path, "r");
    if (!stream)
        return -1;
    if (!fgets(out, (int)out_len, stream)) {
        fclose(stream);
        out[0] = '\0';
        return -1;
    }
    fclose(stream);
    out[strcspn(out, "\r\n")] = '\0';
    return 0;
}

static int vpn_read_counter(const char *path, int64_t *value)
{
    char buffer[64];
    char *end = NULL;
    uint64_t parsed;

    if (!value || vpn_read_line(path, buffer, sizeof(buffer)) != 0)
        return -1;
    errno = 0;
    parsed = strtoull(buffer, &end, 10);
    if (errno || end == buffer || (*end && !isspace((unsigned char)*end)) ||
        parsed > INT64_MAX)
        return -1;
    *value = (int64_t)parsed;
    return 0;
}

static int vpn_interface_probe(const char *root, const char *ifname,
                               char *operstate, size_t operstate_len,
                               int64_t *rx_bytes, int64_t *tx_bytes,
                               int *traffic_available)
{
    char path[512];

    if (traffic_available)
        *traffic_available = 0;
    if (!root || !vpn_safe_ifname(ifname))
        return 0;
    if (snprintf(path, sizeof(path), "%s/%s", root, ifname) >= (int)sizeof(path) ||
        access(path, F_OK) != 0)
        return 0;

    snprintf(path, sizeof(path), "%s/%s/operstate", root, ifname);
    if (vpn_read_line(path, operstate, operstate_len) != 0)
        snprintf(operstate, operstate_len, "%s", "unknown");

    snprintf(path, sizeof(path), "%s/%s/statistics/rx_bytes", root, ifname);
    if (vpn_read_counter(path, rx_bytes) != 0)
        return 1;
    snprintf(path, sizeof(path), "%s/%s/statistics/tx_bytes", root, ifname);
    if (vpn_read_counter(path, tx_bytes) != 0)
        return 1;
    if (traffic_available)
        *traffic_available = 1;
    return 1;
}

static int vpn_prefixed_id_match(const char *runtime_id, const char *configured)
{
    static const char *prefixes[] = { "ovpn-", "wg-", "pptp-", "l2tp-", NULL };
    int i;

    if (!runtime_id || !configured || !configured[0])
        return 0;
    if (!strcmp(runtime_id, configured))
        return 1;
    for (i = 0; prefixes[i]; i++) {
        size_t len = strlen(prefixes[i]);

        if (!strncmp(runtime_id, prefixes[i], len) &&
            !strcmp(runtime_id + len, configured))
            return 1;
    }
    return 0;
}

static int vpn_runtime_item_matches(struct json_object *item,
                                    const char *id, const char *name,
                                    const char *configured_ifname)
{
    const char *runtime_id = vpn_string(item, "id");
    const char *runtime_name = vpn_string(item, "name");
    const char *ifname = vpn_string(item, "ifname");
    const char *device = vpn_string(item, "device");

    if (configured_ifname[0] &&
        (!strcmp(configured_ifname, ifname) || !strcmp(configured_ifname, device)))
        return 1;
    return vpn_prefixed_id_match(runtime_id, id) ||
           vpn_prefixed_id_match(runtime_id, name) ||
           (name[0] && !strcmp(runtime_name, name));
}

static struct json_object *vpn_runtime_match(struct json_object *legacy_runtime,
                                             const char *protocol,
                                             const char *id, const char *name,
                                             const char *configured_ifname)
{
    struct json_object *protocols = vpn_child_object(legacy_runtime, "protocols");
    struct json_object *items;
    int i;

    if (!protocols || !protocol || !protocol[0])
        return NULL;
    items = vpn_child_array(protocols, protocol);
    if (!items)
        return NULL;
    for (i = 0; i < (int)json_object_array_length(items); i++) {
        struct json_object *item = json_object_array_get_idx(items, i);

        if (item && vpn_runtime_item_matches(item, id, name, configured_ifname))
            return item;
    }
    return NULL;
}

static struct json_object *vpn_config_state(const char *source,
                                            struct json_object *settings)
{
    struct json_object *config = json_object_new_object();

    vpn_add_string(config, "state", "saved");
    json_object_object_add(config, "saved", json_object_new_boolean(1));
    vpn_add_null(config, "applying");
    vpn_add_null(config, "applied");
    vpn_add_null(config, "failed");
    vpn_add_string(config, "source", source);
    json_object_object_add(config, "settings", settings);
    return config;
}

static struct json_object *vpn_runtime_state(struct json_object *legacy_runtime,
                                             const char *sys_class_net,
                                             int64_t observed_at,
                                             const char *protocol,
                                             const char *id,
                                             const char *name,
                                             const char *configured_ifname)
{
    struct json_object *runtime = json_object_new_object();
    struct json_object *match = vpn_runtime_match(legacy_runtime, protocol, id, name,
                                                  configured_ifname);
    const char *ifname = configured_ifname;
    char operstate[32] = "";
    int64_t rx_bytes = 0;
    int64_t tx_bytes = 0;
    int traffic_available = 0;
    int present;

    if (match) {
        const char *candidate = vpn_string(match, "ifname");

        if (!candidate[0])
            candidate = vpn_string(match, "device");
        if (candidate[0])
            ifname = candidate;
    }
    present = vpn_interface_probe(sys_class_net, ifname, operstate, sizeof(operstate),
                                  &rx_bytes, &tx_bytes, &traffic_available);

    json_object_object_add(runtime, "available", json_object_new_boolean(present));
    json_object_object_add(runtime, "observed_at", json_object_new_int64(observed_at));
    vpn_add_string(runtime, "source", present ? "kernel_sysfs" : "unavailable");
    vpn_add_string(runtime, "reason",
                   present ? "interface_observed" :
                   (!legacy_runtime ? "vpn_runtime_source_unavailable" :
                    "runtime_interface_not_observed"));
    if (ifname && ifname[0])
        vpn_add_string(runtime, "interface", ifname);
    else
        vpn_add_null(runtime, "interface");
    json_object_object_add(runtime, "interface_present", json_object_new_boolean(present));
    if (present)
        vpn_add_string(runtime, "interface_state", operstate[0] ? operstate : "unknown");
    else
        vpn_add_null(runtime, "interface_state");

    vpn_add_null(runtime, "state");
    vpn_add_null(runtime, "connected");
    vpn_add_string(runtime, "connected_reason", "protocol_session_probe_not_implemented");
    vpn_add_null(runtime, "last_handshake_at");
    vpn_add_null(runtime, "duration_seconds");
    vpn_add_null(runtime, "latency_ms");
    vpn_add_string(runtime, "session_reason", "protocol_session_probe_not_implemented");
    json_object_object_add(runtime, "traffic_available",
                           json_object_new_boolean(traffic_available));
    if (traffic_available) {
        json_object_object_add(runtime, "rx_bytes", json_object_new_int64(rx_bytes));
        json_object_object_add(runtime, "tx_bytes", json_object_new_int64(tx_bytes));
        vpn_add_string(runtime, "traffic_reason", "kernel_interface_counters");
    } else {
        vpn_add_null(runtime, "rx_bytes");
        vpn_add_null(runtime, "tx_bytes");
        vpn_add_string(runtime, "traffic_reason",
                       present ? "interface_counters_unavailable" :
                                 "runtime_interface_not_observed");
    }
    vpn_add_null(runtime, "rx_rate");
    vpn_add_null(runtime, "tx_rate");
    vpn_add_string(runtime, "rate_reason", "authoritative_rate_sampler_not_available");
    return runtime;
}

static struct json_object *vpn_settings(struct json_object *row,
                                        const char *const *keys)
{
    struct json_object *settings = json_object_new_object();
    int i;

    for (i = 0; keys[i]; i++)
        vpn_copy(settings, row, keys[i]);
    return settings;
}

static struct json_object *vpn_tunnel_rows(struct json_object *rows,
                                           const char *kind,
                                           struct json_object *legacy_runtime,
                                           const char *sys_class_net,
                                           int64_t observed_at)
{
    static const char *const server_keys[] = {
        "listen", "address_pool", "local_address", "port", "auth", "routes",
        "dns", "mtu", "mru", "lcp_interval", "force_internet",
        "client_isolation", "vlan_binding", "remark", NULL
    };
    static const char *const client_keys[] = {
        "remote", "iface", "bind_wan", "auth", "username", "local_address",
        "server_address", "routes", "nat", "remark", NULL
    };
    static const char *const site_keys[] = {
        "local_networks", "remote_networks", "peer", "wan", "remark", NULL
    };
    struct json_object *out = json_object_new_array();
    int i;

    if (!rows)
        return out;
    for (i = 0; i < (int)json_object_array_length(rows); i++) {
        struct json_object *row = json_object_array_get_idx(rows, i);
        struct json_object *item;
        struct json_object *settings;
        const char *id;
        const char *name;
        const char *protocol;
        const char *ifname = "";
        const char *source;

        if (!row || !json_object_is_type(row, json_type_object))
            continue;
        id = vpn_string(row, "id");
        name = vpn_string(row, "name");
        protocol = !strcmp(kind, "site") ? vpn_string(row, "type") :
                                             vpn_string(row, "protocol");
        if (!strcmp(kind, "client"))
            ifname = vpn_string(row, "iface");
        else if (!strcmp(kind, "server"))
            ifname = vpn_string(row, "listen");

        item = json_object_new_object();
        vpn_add_string(item, "id", id);
        vpn_add_string(item, "name", name);
        vpn_add_string(item, "protocol", protocol);
        json_object_object_add(item, "enabled",
                               json_object_new_boolean(vpn_boolean(row, "enabled", 0)));
        settings = vpn_settings(row, !strcmp(kind, "server") ? server_keys :
                                     !strcmp(kind, "client") ? client_keys : site_keys);
        source = !strcmp(kind, "server") ? "config.db:vpn_server" :
                 !strcmp(kind, "client") ? "config.db:vpn_client" :
                                             "config.db:vpn_site";
        json_object_object_add(item, "config", vpn_config_state(source, settings));
        json_object_object_add(item, "runtime",
            vpn_runtime_state(legacy_runtime, sys_class_net, observed_at, protocol,
                              id, name, ifname));
        json_object_array_add(out, item);
    }
    return out;
}

static struct json_object *vpn_account_rows(struct json_object *rows,
                                            int64_t observed_at)
{
    static const char *const keys[] = {
        "username", "group", "protocols", "max_sessions", "vlan", "expires",
        "status", NULL
    };
    struct json_object *out = json_object_new_array();
    int i;

    if (!rows)
        return out;
    for (i = 0; i < (int)json_object_array_length(rows); i++) {
        struct json_object *row = json_object_array_get_idx(rows, i);
        struct json_object *item;
        struct json_object *runtime;

        if (!row || !json_object_is_type(row, json_type_object))
            continue;
        item = json_object_new_object();
        vpn_add_string(item, "id", vpn_string(row, "id"));
        vpn_add_string(item, "username", vpn_string(row, "username"));
        json_object_object_add(item, "config",
                               vpn_config_state("config.db:vpn_account",
                                                vpn_settings(row, keys)));
        runtime = json_object_new_object();
        json_object_object_add(runtime, "available", json_object_new_boolean(0));
        json_object_object_add(runtime, "observed_at", json_object_new_int64(observed_at));
        vpn_add_string(runtime, "reason", "account_session_probe_not_implemented");
        vpn_add_null(runtime, "online_sessions");
        json_object_object_add(item, "runtime", runtime);
        json_object_array_add(out, item);
    }
    return out;
}

static struct json_object *vpn_certificate_rows(struct json_object *rows,
                                                int64_t observed_at)
{
    static const char *const keys[] = {
        "name", "type", "used_by", "expires_in_days", "status", NULL
    };
    struct json_object *out = json_object_new_array();
    int i;

    if (!rows)
        return out;
    for (i = 0; i < (int)json_object_array_length(rows); i++) {
        struct json_object *row = json_object_array_get_idx(rows, i);
        struct json_object *item;
        struct json_object *runtime;

        if (!row || !json_object_is_type(row, json_type_object))
            continue;
        item = json_object_new_object();
        vpn_add_string(item, "id", vpn_string(row, "id"));
        vpn_add_string(item, "name", vpn_string(row, "name"));
        json_object_object_add(item, "config",
                               vpn_config_state("config.db:vpn_certificate",
                                                vpn_settings(row, keys)));
        runtime = json_object_new_object();
        json_object_object_add(runtime, "available", json_object_new_boolean(0));
        json_object_object_add(runtime, "observed_at", json_object_new_int64(observed_at));
        vpn_add_string(runtime, "reason", "certificate_runtime_probe_not_implemented");
        vpn_add_null(runtime, "valid_now");
        json_object_object_add(item, "runtime", runtime);
        json_object_array_add(out, item);
    }
    return out;
}

static struct json_object *vpn_capabilities(struct json_object *config,
                                            struct json_object *legacy_runtime,
                                            const char *sys_class_net)
{
    static const char *const writes[] = {
        "server_create", "server_update", "server_delete",
        "client_create", "client_update", "client_delete",
        "site_create", "site_update", "site_delete",
        "account_create", "account_update", "account_delete",
        "certificate_create", "certificate_update", "certificate_delete",
        "config_import", "config_export", NULL
    };
    struct json_object *cap = json_object_new_object();
    struct json_object *protocols = vpn_child_object(config, "capabilities");
    int i;

    json_object_object_add(cap, "read", json_object_new_boolean(1));
    json_object_object_add(cap, "config_read", json_object_new_boolean(1));
    json_object_object_add(cap, "runtime_interface_inventory",
                           json_object_new_boolean(legacy_runtime != NULL));
    json_object_object_add(cap, "runtime_status", json_object_new_boolean(0));
    json_object_object_add(cap, "protocol_session_status", json_object_new_boolean(0));
    json_object_object_add(cap, "traffic_stats",
                           json_object_new_boolean(access(sys_class_net, R_OK) == 0));
    json_object_object_add(cap, "traffic_rates", json_object_new_boolean(0));
    json_object_object_add(cap, "latency", json_object_new_boolean(0));
    json_object_object_add(cap, "online_users", json_object_new_boolean(0));
    json_object_object_add(cap, "transaction", json_object_new_boolean(0));
    json_object_object_add(cap, "readback", json_object_new_boolean(0));
    json_object_object_add(cap, "rollback", json_object_new_boolean(0));
    for (i = 0; writes[i]; i++)
        json_object_object_add(cap, writes[i], json_object_new_boolean(0));
    json_object_object_add(cap, "protocols",
                           protocols ? json_object_get(protocols) :
                                       json_object_new_object());
    return cap;
}

static struct json_object *vpn_capability_reasons(struct json_object *legacy_runtime)
{
    struct json_object *reasons = json_object_new_object();

    vpn_add_string(reasons, "writes",
                   "transaction_readback_rollback_not_implemented");
    vpn_add_string(reasons, "runtime_status",
                   "protocol_session_probes_not_implemented");
    vpn_add_string(reasons, "runtime_interface_inventory",
                   legacy_runtime ? "legacy_runtime_inventory_available" :
                                    "vpn_runtime_source_unavailable");
    vpn_add_string(reasons, "traffic_rates",
                   "authoritative_rate_sampler_not_available");
    vpn_add_string(reasons, "latency", "latency_probe_not_implemented");
    vpn_add_string(reasons, "online_users",
                   "account_session_probe_not_implemented");
    return reasons;
}

static struct json_object *vpn_summary(struct json_object *servers,
                                       struct json_object *clients,
                                       struct json_object *sites,
                                       struct json_object *accounts,
                                       struct json_object *certificates)
{
    struct json_object *summary = json_object_new_object();

    json_object_object_add(summary, "server_count",
                           json_object_new_int((int)json_object_array_length(servers)));
    json_object_object_add(summary, "client_count",
                           json_object_new_int((int)json_object_array_length(clients)));
    json_object_object_add(summary, "site_count",
                           json_object_new_int((int)json_object_array_length(sites)));
    json_object_object_add(summary, "account_count",
                           json_object_new_int((int)json_object_array_length(accounts)));
    json_object_object_add(summary, "certificate_count",
                           json_object_new_int((int)json_object_array_length(certificates)));
    vpn_add_null(summary, "active_tunnels");
    vpn_add_null(summary, "online_users");
    vpn_add_null(summary, "rx_rate");
    vpn_add_null(summary, "tx_rate");
    vpn_add_string(summary, "runtime_reason",
                   "protocol_session_probes_not_implemented");
    return summary;
}

struct json_object *webd_vpn_aggregate_data_at(struct json_object *config,
                                               struct json_object *legacy_runtime,
                                               const char *sys_class_net,
                                               int64_t observed_at)
{
    struct json_object *data;
    struct json_object *servers;
    struct json_object *clients;
    struct json_object *sites;
    struct json_object *accounts;
    struct json_object *certificates;
    struct json_object *teleport;

    if (!config || !json_object_is_type(config, json_type_object) ||
        !sys_class_net || !sys_class_net[0])
        return NULL;
    if (observed_at <= 0)
        observed_at = (int64_t)time(NULL);

    servers = vpn_tunnel_rows(vpn_child_array(config, "servers"), "server",
                              legacy_runtime, sys_class_net, observed_at);
    clients = vpn_tunnel_rows(vpn_child_array(config, "clients"), "client",
                              legacy_runtime, sys_class_net, observed_at);
    sites = vpn_tunnel_rows(vpn_child_array(config, "site_to_site"), "site",
                            legacy_runtime, sys_class_net, observed_at);
    accounts = vpn_account_rows(vpn_child_array(config, "accounts"), observed_at);
    certificates = vpn_certificate_rows(vpn_child_array(config, "certificates"),
                                         observed_at);

    data = json_object_new_object();
    vpn_add_string(data, "contract_version", "vpn-management.v1");
    json_object_object_add(data, "observed_at", json_object_new_int64(observed_at));
    json_object_object_add(data, "global",
                           vpn_child_object(config, "global") ?
                           json_object_get(vpn_child_object(config, "global")) :
                           json_object_new_object());
    json_object_object_add(data, "servers", servers);
    json_object_object_add(data, "clients", clients);
    json_object_object_add(data, "site_to_site", sites);
    json_object_object_add(data, "accounts", accounts);
    json_object_object_add(data, "certificates", certificates);
    json_object_object_add(data, "summary",
                           vpn_summary(servers, clients, sites, accounts, certificates));
    teleport = json_object_new_object();
    json_object_object_add(teleport, "available", json_object_new_boolean(0));
    vpn_add_string(teleport, "reason", "not_implemented");
    json_object_object_add(data, "teleport", teleport);
    json_object_object_add(data, "capabilities",
                           vpn_capabilities(config, legacy_runtime, sys_class_net));
    json_object_object_add(data, "capability_reasons",
                           vpn_capability_reasons(legacy_runtime));
    return data;
}

struct json_object *webd_vpn_aggregate_data(struct json_object *config,
                                            struct json_object *legacy_runtime)
{
    return webd_vpn_aggregate_data_at(config, legacy_runtime, VPN_SYS_CLASS_NET,
                                      (int64_t)time(NULL));
}

struct json_object *webd_vpn_resource_view(struct json_object *snapshot,
                                           const char *resource)
{
    struct json_object *items;
    struct json_object *view;

    if (!snapshot || !resource || !resource[0])
        return NULL;
    items = vpn_child_array(snapshot, resource);
    if (!items)
        return NULL;
    view = json_object_new_object();
    vpn_copy(view, snapshot, "contract_version");
    vpn_copy(view, snapshot, "observed_at");
    json_object_object_add(view, "resource", json_object_new_string(resource));
    json_object_object_add(view, "items", json_object_get(items));
    vpn_copy(view, snapshot, "capabilities");
    vpn_copy(view, snapshot, "capability_reasons");
    return view;
}
