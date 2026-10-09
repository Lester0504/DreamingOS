// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>
 *
 * Port / VLAN manager subsystem (Phase 6X).
 *
 * The whole port-topology read + DSA VLAN/profile write subsystem lifted
 * verbatim out of jmx_app_api.c: the per-port filter/gateway/neighbor/MAC
 * contract builders and the topology port write-capabilities probe; the UCI
 * bridge-VLAN mutation executor with snapshot + reload-runtime + readback +
 * local-reachability health transaction; the plan/preview/effective-target
 * builders and strict validators; and the
 * /api/v1/topology/node/ports{,/preview,/apply,/batch,/validate,/profiles}
 * response builders.
 *
 * handle_client reaches this subsystem only via response builders it DISPATCHES
 * plus a few helpers used in the route match — none are jmx_api_route table rows
 * — so no route moved. The nine entry points are declared in
 * api_ports_internal.h.
 *
 * Borrowed from jmx_app_api.c (defs stay there): the network snapshot-restore /
 * reload-runtime / local-reachability-probe helpers, the shared string compare,
 * the safe-token and MAC-normalize helpers — all declared in
 * api_ports_internal.h. jmx_config_apply/confirm and the three relocated network
 * macros come from the public jmx_app_api.h; jmx_cache_invalidate from
 * jmx_app_cache.h.
 *
 * The eight file-local helpers that are forward-referenced within this TU keep
 * their `static` linkage and are forward-declared just below, carried verbatim
 * from jmx_app_api.c's old preamble.
 *
 * This file is a pure extraction: no behaviour changed, no route moved.
 */
#include <stdbool.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <signal.h>
#include <unistd.h>
#include <sys/wait.h>
#include <uci.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <json-c/json.h>

#include "webd_http_req.h"
#include "jmx_strbuf.h"
#include "../jmx_app_api.h"
#include "../jmx_app_cache.h"
#include "api_error.h"
#include "api_json.h"
#include "api_request.h"
#include "api_topology.h"
#include "api_ubus.h"
#include "api_ports_internal.h"
#include "../../safeops/port_revision.h"

extern sqlite3 *g_app_db;
extern sqlite3 *g_config_db;

/* File-local helpers forward-referenced within this TU (verbatim from the old
 * jmx_app_api.c preamble); their definitions live below and stay `static`. */
static struct json_object *webd_port_effective_vlan_target(struct json_object *body,
                                                           struct json_object *warnings);
static int webd_file_read_first_line(const char *path, char *out, size_t out_len);
static int webd_port_bridge_vlan_readback(const char *bridge_name,
                                          const char *ifname,
                                          int native_vlan,
                                          struct json_object *tagged,
                                          struct json_object *rb);
static int webd_port_ifname_strict_ok(const char *s);
static int webd_port_uci_section_strict_ok(const char *s);
static int webd_port_vlan_id_ok(int vlan, int allow_zero);
static int webd_port_tagged_vlans_strict_ok(struct json_object *arr,
                                             char *err, size_t err_len);
static int webd_text_has_vlan_token(const char *text, int vlan);

static int webd_port_matches_filter(struct json_object *port,
                                    const char *id,
                                    const char *mac,
                                    const char *port_id,
                                    const char *ifname)
{
    if (!port)
        return 0;
    if (id && id[0] &&
        !webd_str_eq_nonempty(app_nc_json_str(port, "device_id", ""), id) &&
        !webd_str_eq_nonempty(app_nc_json_str(port, "device_mac", ""), id))
        return 0;
    if (mac && mac[0] &&
        !webd_str_eq_nonempty(app_nc_json_str(port, "device_mac", ""), mac) &&
        !webd_str_eq_nonempty(app_nc_json_str(port, "device_id", ""), mac))
        return 0;
    if (port_id && port_id[0] &&
        !webd_str_eq_nonempty(app_nc_json_str(port, "port_id", ""), port_id) &&
        !webd_str_eq_nonempty(app_nc_json_str(port, "name", ""), port_id) &&
        !webd_str_eq_nonempty(app_nc_json_str(port, "ifname", ""), port_id))
        return 0;
    if (ifname && ifname[0] &&
        !webd_str_eq_nonempty(app_nc_json_str(port, "ifname", ""), ifname) &&
        !webd_str_eq_nonempty(app_nc_json_str(port, "name", ""), ifname))
        return 0;
    return 1;
}

static struct json_object *webd_find_gateway_for_port(struct json_object *gateways,
                                                      struct json_object *port)
{
    const char *device_id = app_nc_json_str(port, "device_id", "");
    const char *device_mac = app_nc_json_str(port, "device_mac", "");
    int i, n;

    if (!gateways || !json_object_is_type(gateways, json_type_array))
        return NULL;
    n = json_object_array_length(gateways);
    for (i = 0; i < n; i++) {
        struct json_object *g = json_object_array_get_idx(gateways, i);
        if (webd_str_eq_nonempty(app_nc_json_str(g, "id", ""), device_id) ||
            webd_str_eq_nonempty(app_nc_json_str(g, "mac", ""), device_mac))
            return g;
    }
    return NULL;
}

static void webd_add_port_related_links(struct json_object *out,
                                        struct json_object *links,
                                        struct json_object *port)
{
    struct json_object *arr = json_object_new_array();
    const char *port_id = app_nc_json_str(port, "port_id", "");
    const char *ifname = app_nc_json_str(port, "ifname", app_nc_json_str(port, "name", ""));
    const char *device_id = app_nc_json_str(port, "device_id", "");
    const char *device_mac = app_nc_json_str(port, "device_mac", "");
    int complete = 1;
    int i, n;

    if (links && json_object_is_type(links, json_type_array)) {
        n = json_object_array_length(links);
        for (i = 0; i < n; i++) {
            struct json_object *l = json_object_array_get_idx(links, i);
            const char *up_port = app_nc_json_str(l, "uplink_port_id", "");
            const char *down_port = app_nc_json_str(l, "downlink_port_id", "");
            const char *up_node = app_nc_json_str(l, "uplink_node_id", "");
            const char *down_node = app_nc_json_str(l, "downlink_node_id", "");
            const char *up_mac = app_nc_json_str(l, "uplink_mac", "");
            const char *down_mac = app_nc_json_str(l, "downlink_mac", "");
            const char *link_device = app_nc_json_str(l, "device", "");
            const char *link_port = app_nc_json_str(l, "port", "");
            const char *switch_port = app_nc_json_str(l, "switch_port", "");
            const char *fdb_ifname = app_nc_json_str(l, "bridge_fdb_ifname", "");
            int has_port_evidence;
            int matched = 0;

            if (webd_str_eq_nonempty(up_port, port_id) ||
                webd_str_eq_nonempty(down_port, port_id) ||
                webd_str_eq_nonempty(up_port, ifname) ||
                webd_str_eq_nonempty(down_port, ifname) ||
                webd_str_eq_nonempty(link_device, ifname) ||
                webd_str_eq_nonempty(link_port, ifname) ||
                webd_str_eq_nonempty(switch_port, ifname) ||
                webd_str_eq_nonempty(fdb_ifname, ifname))
                matched = 1;
            has_port_evidence = up_port[0] || down_port[0] || link_device[0] ||
                                link_port[0] || switch_port[0] || fdb_ifname[0];
            if (!matched && !has_port_evidence &&
                (webd_str_eq_nonempty(up_node, device_id) ||
                 webd_str_eq_nonempty(down_node, device_id) ||
                 webd_str_eq_nonempty(up_mac, device_mac) ||
                 webd_str_eq_nonempty(down_mac, device_mac))) {
                const char *role = app_nc_json_str(port, "role", "");
                const char *path_role = app_nc_json_str(l, "path_role", "");
                if ((!strcmp(role, "wan") && strstr(path_role, "internet_to_gateway")) ||
                    (!strcmp(role, "lan") && strstr(path_role, "gateway_to_"))) {
                    matched = 1;
                    complete = 0;
                }
            }
            if (matched)
                json_object_array_add(arr, json_object_get(l));
        }
    }
    json_object_object_add(out, "links", arr);
    json_object_object_add(out, "port_match_complete", json_object_new_boolean(complete));
}

static struct json_object *webd_find_infra_client(struct json_object *clients,
                                                  const char *id,
                                                  const char *mac)
{
    int i, n;

    if (!clients || !json_object_is_type(clients, json_type_array))
        return NULL;
    n = json_object_array_length(clients);
    for (i = 0; i < n; i++) {
        struct json_object *c = json_object_array_get_idx(clients, i);

        if ((id && id[0] &&
             (webd_str_eq_nonempty(app_nc_json_str(c, "id", ""), id) ||
              webd_str_eq_nonempty(app_nc_json_str(c, "mac", ""), id))) ||
            (mac && mac[0] &&
             (webd_str_eq_nonempty(app_nc_json_str(c, "mac", ""), mac) ||
              webd_str_eq_nonempty(app_nc_json_str(c, "id", ""), mac))))
            return c;
    }
    return NULL;
}

static int webd_port_neighbor_seen(struct json_object *neighbors,
                                   const char *id,
                                   const char *mac)
{
    int i, n;

    if (!neighbors || !json_object_is_type(neighbors, json_type_array))
        return 0;
    n = json_object_array_length(neighbors);
    for (i = 0; i < n; i++) {
        struct json_object *cur = json_object_array_get_idx(neighbors, i);

        if ((id && id[0] &&
             (webd_str_eq_nonempty(app_nc_json_str(cur, "id", ""), id) ||
              webd_str_eq_nonempty(app_nc_json_str(cur, "mac", ""), id))) ||
            (mac && mac[0] &&
             (webd_str_eq_nonempty(app_nc_json_str(cur, "mac", ""), mac) ||
              webd_str_eq_nonempty(app_nc_json_str(cur, "id", ""), mac))))
            return 1;
    }
    return 0;
}

static void webd_add_port_neighbor_from_link(struct json_object *neighbors,
                                             struct json_object *link,
                                             struct json_object *clients,
                                             struct json_object *port,
                                             int *client_count,
                                             int *wan_peer_count,
                                             int *fdb_observed_count,
                                             int *fdb_confirmed_count)
{
    const char *device_id = app_nc_json_str(port, "device_id", "");
    const char *device_mac = app_nc_json_str(port, "device_mac", "");
    const char *ifname = app_nc_json_str(port, "ifname", app_nc_json_str(port, "name", ""));
    const char *up_node = app_nc_json_str(link, "uplink_node_id", "");
    const char *down_node = app_nc_json_str(link, "downlink_node_id", "");
    const char *up_mac = app_nc_json_str(link, "uplink_mac", "");
    const char *down_mac = app_nc_json_str(link, "downlink_mac", "");
    const char *path_role = app_nc_json_str(link, "path_role", "");
    const char *link_type = app_nc_json_str(link, "type", "");
    const char *remote_id = down_node;
    const char *remote_mac = down_mac;
    const char *neighbor_type = "CLIENT";
    char normalized_remote_mac[32] = "";
    struct json_object *client = NULL;
    struct json_object *traffic = NULL;
    struct json_object *n = NULL;

    if (!neighbors || !link || !port)
        return;

    if (!strcmp(link_type, "WAN") || strstr(path_role, "internet_to_gateway")) {
        remote_id = up_node;
        remote_mac = up_mac;
        neighbor_type = "ISP";
    } else if (webd_str_eq_nonempty(down_node, device_id) ||
               webd_str_eq_nonempty(down_node, device_mac) ||
               webd_str_eq_nonempty(down_mac, device_mac)) {
        remote_id = up_node;
        remote_mac = up_mac;
    } else {
        remote_id = down_node;
        remote_mac = down_mac;
    }

    if (!remote_id[0] && !remote_mac[0])
        return;
    if (webd_normalize_mac_text(remote_mac, normalized_remote_mac,
                                sizeof(normalized_remote_mac)) != 0)
        normalized_remote_mac[0] = '\0';
    if (webd_port_neighbor_seen(neighbors, remote_id, normalized_remote_mac))
        return;

    client = webd_find_infra_client(clients, remote_id, normalized_remote_mac);
    if (client) {
        neighbor_type = "CLIENT";
        if (client_count) (*client_count)++;
    } else if (!strcmp(neighbor_type, "ISP")) {
        if (wan_peer_count) (*wan_peer_count)++;
    }
    if (app_nc_json_bool(link, "bridge_fdb_observed", 0) && fdb_observed_count)
        (*fdb_observed_count)++;
    if (app_nc_json_bool(link, "bridge_fdb_confirmed", 0) && fdb_confirmed_count)
        (*fdb_confirmed_count)++;

    n = json_object_new_object();
    json_object_object_add(n, "id", json_object_new_string(remote_id[0] ? remote_id : normalized_remote_mac));
    json_object_object_add(n, "peer_id", json_object_new_string(remote_id));
    json_object_object_add(n, "mac", normalized_remote_mac[0] ?
                           json_object_new_string(normalized_remote_mac) : json_object_new_null());
    json_object_object_add(n, "peer_mac", normalized_remote_mac[0] ?
                           json_object_new_string(normalized_remote_mac) : json_object_new_null());
    json_object_object_add(n, "peer_source", json_object_new_string(
                           normalized_remote_mac[0] ? "topology_link_mac" :
                           (!strcmp(neighbor_type, "ISP") ? "topology_link_logical_peer" :
                            "topology_link_id")));
    json_object_object_add(n, "type", json_object_new_string(neighbor_type));
    json_object_object_add(n, "role", json_object_new_string(!strcmp(neighbor_type, "ISP") ? "internet" : "client"));
    json_object_object_add(n, "state", json_object_new_string(client ? app_nc_json_str(client, "state", "online") : "online"));
    json_object_object_add(n, "name", json_object_new_string(client ? app_nc_json_str(client, "name", remote_id) :
                                                            (!strcmp(neighbor_type, "ISP") ?
                                                             app_nc_json_str(link, "wan_id", "ISP") : remote_id)));
    if (client) {
        webd_json_copy_key(n, "ip", client, "ip");
        webd_json_copy_key(n, "ipv4", client, "ipv4");
        webd_json_copy_key(n, "ipv6_global", client, "ipv6_global");
        webd_json_copy_key(n, "model", client, "model");
        webd_json_copy_key(n, "image", client, "image");
        webd_json_copy_key(n, "icon", client, "icon");
    }
    json_object_object_add(n, "local_ifname", json_object_new_string(ifname));
    json_object_object_add(n, "link_id", json_object_new_string(app_nc_json_str(link, "id", "")));
    json_object_object_add(n, "path_role", json_object_new_string(path_role));
    json_object_object_add(n, "link_type", json_object_new_string(link_type));
    json_object_object_add(n, "relationship_source", json_object_new_string(app_nc_json_str(link, "relationship_source", "")));
    json_object_object_add(n, "relationship_confidence", json_object_new_int(app_nc_json_int(link, "relationship_confidence", 0)));
    json_object_object_add(n, "relationship_complete", json_object_new_boolean(app_nc_json_bool(link, "relationship_complete", 0)));
    json_object_object_add(n, "port_evidence_source", json_object_new_string(app_nc_json_str(link, "port_evidence_source", "")));
    json_object_object_add(n, "port_match_source", json_object_new_string(app_nc_json_str(link, "port_match_source", "")));
    json_object_object_add(n, "bridge_fdb_observed", json_object_new_boolean(app_nc_json_bool(link, "bridge_fdb_observed", 0)));
    json_object_object_add(n, "bridge_fdb_confirmed", json_object_new_boolean(app_nc_json_bool(link, "bridge_fdb_confirmed", 0)));
    json_object_object_add(n, "bridge_fdb_conflict", json_object_new_boolean(app_nc_json_bool(link, "bridge_fdb_conflict", 0)));
    json_object_object_add(n, "bridge_fdb_ifname", json_object_new_string(app_nc_json_str(link, "bridge_fdb_ifname", "")));
    json_object_object_add(n, "bridge_fdb_port_no", json_object_new_string(app_nc_json_str(link, "bridge_fdb_port_no", "")));
    json_object_object_add(n, "downstream_switch_port_known", json_object_new_boolean(0));
    json_object_object_add(n, "reason", json_object_new_string(app_nc_json_bool(link, "bridge_fdb_observed", 0) ?
                                                               "topology_link_with_local_bridge_fdb_evidence" :
                                                               "topology_link_evidence"));
    traffic = webd_obj_child_obj(client, "traffic");
    if (!traffic)
        traffic = webd_obj_child_obj(link, "traffic");
    json_object_object_add(n, "traffic", traffic ? json_object_get(traffic) : json_object_new_object());
    json_object_array_add(neighbors, n);
}

static void webd_add_port_mac_contract(struct json_object *out,
                                       struct json_object *port)
{
    const char *ifname = app_nc_json_str(port, "ifname",
                                        app_nc_json_str(port, "name", ""));
    const char *peer_id = app_nc_json_str(out, "connected_node_id", "");
    const char *connected_mac = app_nc_json_str(out, "connected_mac", "");
    char path[256];
    char local_mac[64] = "";
    char normalized[32] = "";

    if (ifname[0] && webd_safe_token(ifname)) {
        snprintf(path, sizeof(path), "/sys/class/net/%s/address", ifname);
        if (webd_file_read_first_line(path, local_mac, sizeof(local_mac)) == 0 &&
            webd_normalize_mac_text(local_mac, normalized, sizeof(normalized)) == 0) {
            json_object_object_add(out, "local_mac", json_object_new_string(normalized));
            json_object_object_add(out, "mac_source", json_object_new_string("sysfs:address"));
        } else {
            json_object_object_add(out, "local_mac", json_object_new_null());
            json_object_object_add(out, "mac_source", json_object_new_string("unavailable"));
        }
    }

    json_object_object_add(out, "peer_id", peer_id[0] ?
                           json_object_new_string(peer_id) : json_object_new_null());
    if (webd_normalize_mac_text(connected_mac, normalized, sizeof(normalized)) == 0) {
        json_object_object_add(out, "connected_mac", json_object_new_string(normalized));
        json_object_object_add(out, "peer_mac", json_object_new_string(normalized));
        json_object_object_add(out, "peer_source", json_object_new_string("topology_link_mac"));
    } else {
        json_object_object_add(out, "connected_mac", json_object_new_null());
        json_object_object_add(out, "peer_mac", json_object_new_null());
        json_object_object_add(out, "peer_source", json_object_new_string(
                               peer_id[0] ? "topology_link_logical_peer" : "unavailable"));
    }
}

static void webd_add_port_neighbor_from_fdb(struct json_object *neighbors,
                                            struct json_object *entry,
                                            struct json_object *clients,
                                            struct json_object *port,
                                            int *fdb_only_count)
{
    const char *ifname = app_nc_json_str(port, "ifname", app_nc_json_str(port, "name", ""));
    const char *entry_ifname = app_nc_json_str(entry, "ifname", "");
    const char *mac = app_nc_json_str(entry, "mac", "");
    struct json_object *client = NULL;
    struct json_object *n = NULL;
    struct json_object *traffic = NULL;

    if (!neighbors || !entry || !ifname[0] || !entry_ifname[0] || strcmp(ifname, entry_ifname))
        return;
    if (!mac[0] || app_nc_json_bool(entry, "local", 0))
        return;
    if (webd_port_neighbor_seen(neighbors, mac, mac))
        return;

    client = webd_find_infra_client(clients, mac, mac);
    n = json_object_new_object();
    json_object_object_add(n, "id", json_object_new_string(mac));
    json_object_object_add(n, "mac", json_object_new_string(mac));
    json_object_object_add(n, "type", json_object_new_string(client ? "CLIENT" : "UNKNOWN"));
    json_object_object_add(n, "role", json_object_new_string("client"));
    json_object_object_add(n, "state", json_object_new_string(client ? app_nc_json_str(client, "state", "online") : "unknown"));
    json_object_object_add(n, "name", json_object_new_string(client ? app_nc_json_str(client, "name", mac) : mac));
    if (client) {
        webd_json_copy_key(n, "ip", client, "ip");
        webd_json_copy_key(n, "ipv4", client, "ipv4");
        webd_json_copy_key(n, "ipv6_global", client, "ipv6_global");
        webd_json_copy_key(n, "model", client, "model");
        webd_json_copy_key(n, "image", client, "image");
        webd_json_copy_key(n, "icon", client, "icon");
    }
    json_object_object_add(n, "local_ifname", json_object_new_string(ifname));
    json_object_object_add(n, "relationship_source", json_object_new_string("bridge_fdb"));
    json_object_object_add(n, "relationship_confidence", json_object_new_int(client ? 70 : 55));
    json_object_object_add(n, "relationship_complete", json_object_new_boolean(0));
    json_object_object_add(n, "port_evidence_source", json_object_new_string(app_nc_json_str(entry, "source", "brctl showmacs")));
    json_object_object_add(n, "bridge_fdb_observed", json_object_new_boolean(1));
    json_object_object_add(n, "bridge_fdb_confirmed", json_object_new_boolean(0));
    json_object_object_add(n, "bridge_fdb_conflict", json_object_new_boolean(0));
    json_object_object_add(n, "bridge_fdb_ifname", json_object_new_string(entry_ifname));
    json_object_object_add(n, "bridge_fdb_port_no", json_object_new_string(app_nc_json_str(entry, "port_no", "")));
    json_object_object_add(n, "downstream_switch_port_known", json_object_new_boolean(0));
    json_object_object_add(n, "reason", json_object_new_string(app_nc_json_str(entry, "reason", "local_bridge_fdb_observation_only")));
    traffic = webd_obj_child_obj(client, "traffic");
    json_object_object_add(n, "traffic", traffic ? json_object_get(traffic) : json_object_new_object());
    json_object_array_add(neighbors, n);
    if (fdb_only_count)
        (*fdb_only_count)++;
}

static void webd_add_port_neighbor_from_lldp(struct json_object *neighbors,
                                             struct json_object *nb,
                                             struct json_object *port,
                                             int *lldp_count)
{
    const char *ifname = app_nc_json_str(port, "ifname", app_nc_json_str(port, "name", ""));
    const char *local_ifname = app_nc_json_str(nb, "local_ifname",
                                               app_nc_json_str(nb, "local_port", ""));
    const char *chassis = app_nc_json_str(nb, "remote_chassis_id", "");
    const char *name = app_nc_json_str(nb, "remote_name", "");
    const char *remote_port = app_nc_json_str(nb, "remote_port_id", "");
    const char *inferred_type = app_nc_json_str(nb, "inferred_type", "DEVICE");
    char id[256];
    struct json_object *n = NULL;

    if (!neighbors || !nb || !ifname[0] || !local_ifname[0] || strcmp(ifname, local_ifname))
        return;
    snprintf(id, sizeof(id), "%s", chassis[0] ? chassis : (name[0] ? name : remote_port));
    if (!id[0] || webd_port_neighbor_seen(neighbors, id, id))
        return;

    n = json_object_new_object();
    json_object_object_add(n, "id", json_object_new_string(id));
    json_object_object_add(n, "mac", json_object_new_string(chassis));
    json_object_object_add(n, "type", json_object_new_string(inferred_type && inferred_type[0] ? inferred_type : "DEVICE"));
    json_object_object_add(n, "role", json_object_new_string(!strcmp(inferred_type, "AP") ? "access_point" :
                                                            (!strcmp(inferred_type, "SWITCH") ? "switch" : "device")));
    json_object_object_add(n, "state", json_object_new_string("online"));
    json_object_object_add(n, "name", json_object_new_string(name[0] ? name : id));
    json_object_object_add(n, "local_ifname", json_object_new_string(ifname));
    json_object_object_add(n, "remote_port_id", json_object_new_string(remote_port));
    json_object_object_add(n, "remote_port_description", json_object_new_string(app_nc_json_str(nb, "remote_port_description", "")));
    json_object_object_add(n, "relationship_source", json_object_new_string("lldpcli.normalized_neighbors"));
    json_object_object_add(n, "relationship_confidence", json_object_new_int(90));
    json_object_object_add(n, "relationship_complete", json_object_new_boolean(1));
    json_object_object_add(n, "port_evidence_source", json_object_new_string("lldpcli"));
    json_object_object_add(n, "bridge_fdb_observed", json_object_new_boolean(0));
    json_object_object_add(n, "downstream_switch_port_known", json_object_new_boolean(1));
    webd_json_copy_key(n, "remote_mgmt_ips", nb, "remote_mgmt_ips");
    webd_json_copy_key(n, "capabilities", nb, "capabilities");
    json_object_object_add(n, "lldp", json_object_get(nb));
    json_object_object_add(n, "traffic", json_object_new_object());
    json_object_array_add(neighbors, n);
    if (lldp_count)
        (*lldp_count)++;
}

static void webd_add_port_neighbors(struct json_object *out,
                                    struct json_object *related_links,
                                    struct json_object *clients,
                                    struct json_object *discovery,
                                    struct json_object *port)
{
    struct json_object *neighbors = json_object_new_array();
    struct json_object *summary = json_object_new_object();
    struct json_object *limitations = json_object_new_array();
    struct json_object *bridge_fdb = webd_obj_child_obj(discovery, "bridge_fdb");
    struct json_object *fdb_entries = webd_obj_child_array(bridge_fdb, "entries");
    struct json_object *lldp = webd_obj_child_obj(discovery, "lldp");
    struct json_object *lldp_neighbors = webd_obj_child_array(lldp, "normalized_neighbors");
    const char *fdb_scope = app_nc_json_str(bridge_fdb, "scope", "");
    int client_count = 0;
    int wan_peer_count = 0;
    int fdb_observed_count = 0;
    int fdb_confirmed_count = 0;
    int fdb_only_count = 0;
    int lldp_count = 0;
    int i, n;

    if (related_links && json_object_is_type(related_links, json_type_array)) {
        n = json_object_array_length(related_links);
        for (i = 0; i < n; i++)
            webd_add_port_neighbor_from_link(neighbors, json_object_array_get_idx(related_links, i),
                                             clients, port, &client_count, &wan_peer_count,
                                             &fdb_observed_count, &fdb_confirmed_count);
    }
    if (fdb_entries && json_object_is_type(fdb_entries, json_type_array)) {
        n = json_object_array_length(fdb_entries);
        for (i = 0; i < n; i++)
            webd_add_port_neighbor_from_fdb(neighbors, json_object_array_get_idx(fdb_entries, i),
                                            clients, port, &fdb_only_count);
    }
    if (lldp_neighbors && json_object_is_type(lldp_neighbors, json_type_array)) {
        n = json_object_array_length(lldp_neighbors);
        for (i = 0; i < n; i++)
            webd_add_port_neighbor_from_lldp(neighbors, json_object_array_get_idx(lldp_neighbors, i),
                                             port, &lldp_count);
    }

    if (fdb_scope && !strcmp(fdb_scope, "local_bridge_only"))
        json_object_array_add(limitations, json_object_new_string("local_bridge_fdb_only_downstream_switch_port_unknown"));
    if (!lldp || !app_nc_json_bool(lldp, "available", 0))
        json_object_array_add(limitations, json_object_new_string("lldp_unavailable_or_no_neighbors"));
    json_object_array_add(limitations, json_object_new_string("managed_switch_fdb_api_not_integrated"));

    json_object_object_add(summary, "count", json_object_new_int((int)json_object_array_length(neighbors)));
    json_object_object_add(summary, "client_count", json_object_new_int(client_count));
    json_object_object_add(summary, "wan_peer_count", json_object_new_int(wan_peer_count));
    json_object_object_add(summary, "fdb_observed_count", json_object_new_int(fdb_observed_count));
    json_object_object_add(summary, "fdb_confirmed_count", json_object_new_int(fdb_confirmed_count));
    json_object_object_add(summary, "fdb_only_count", json_object_new_int(fdb_only_count));
    json_object_object_add(summary, "lldp_count", json_object_new_int(lldp_count));
    json_object_object_add(summary, "source", json_object_new_string("topology_infrastructure.links+bridge_fdb+lldp"));
    json_object_object_add(summary, "scope", json_object_new_string(fdb_scope[0] ? fdb_scope : "runtime_evidence"));
    json_object_object_add(summary, "complete", json_object_new_boolean(lldp_count > 0 || fdb_confirmed_count > 0));
    json_object_object_add(summary, "reason",
                           json_object_new_string((lldp_count > 0 || fdb_confirmed_count > 0) ?
                                                  "runtime_neighbor_evidence_available" :
                                                  "local_runtime_evidence_only"));
    json_object_object_add(summary, "limitations", limitations);
    json_object_object_add(out, "neighbors", neighbors);
    json_object_object_add(out, "neighbor_summary", summary);
}

static int webd_port_cap_array_add_unique_str(struct json_object *arr, const char *s)
{
    int i, n;

    if (!arr || !json_object_is_type(arr, json_type_array) || !s || !s[0])
        return 0;
    n = (int)json_object_array_length(arr);
    for (i = 0; i < n; i++) {
        const char *cur = json_object_get_string(json_object_array_get_idx(arr, i));
        if (cur && !strcmp(cur, s))
            return 0;
    }
    json_object_array_add(arr, json_object_new_string(s));
    return 1;
}

static void webd_topology_port_poe_cap_summary(struct json_object *cap,
                                               struct json_object *ports,
                                               struct json_object *supported,
                                               struct json_object *unsupported)
{
    struct json_object *controllers = json_object_new_array();
    const char *reason = "";
    int port_count = 0;
    int poe_seen = 0;
    int poe_supported = 0;
    int poe_runtime_read = 0;
    int controller_count = 0;
    int i, n;

    if (!cap)
        return;
    if (ports && json_object_is_type(ports, json_type_array)) {
        n = (int)json_object_array_length(ports);
        for (i = 0; i < n; i++) {
            struct json_object *p = json_object_array_get_idx(ports, i);
            struct json_object *poe = webd_obj_child_obj(p, "poe");
            struct json_object *probe = poe ? webd_obj_child_obj(poe, "controller_probe") : NULL;
            struct json_object *arr = probe ? webd_obj_child_array(probe, "controllers") : NULL;
            const char *r = poe ? app_nc_json_str(poe, "reason", "") : "";
            int j, m;

            port_count++;
            if (!poe)
                continue;
            poe_seen++;
            if (!reason[0] && r && r[0])
                reason = r;
            if (app_nc_json_bool(poe, "supported", 0))
                poe_supported++;
            if (app_nc_json_bool(poe, "runtime_read", 0))
                poe_runtime_read++;
            controller_count += app_nc_json_int(poe, "controller_count", 0);
            if (arr && json_object_is_type(arr, json_type_array)) {
                m = (int)json_object_array_length(arr);
                for (j = 0; j < m; j++)
                    webd_port_cap_array_add_unique_str(controllers,
                        json_object_get_string(json_object_array_get_idx(arr, j)));
            }
        }
    } else if (ports && json_object_is_type(ports, json_type_object)) {
        struct json_object *poe = webd_obj_child_obj(ports, "poe");
        struct json_object *probe = poe ? webd_obj_child_obj(poe, "controller_probe") : NULL;
        struct json_object *arr = probe ? webd_obj_child_array(probe, "controllers") : NULL;
        int j, m;

        port_count = 1;
        if (poe) {
            poe_seen = 1;
            reason = app_nc_json_str(poe, "reason", "");
            if (app_nc_json_bool(poe, "supported", 0))
                poe_supported = 1;
            if (app_nc_json_bool(poe, "runtime_read", 0))
                poe_runtime_read = 1;
            controller_count = app_nc_json_int(poe, "controller_count", 0);
            if (arr && json_object_is_type(arr, json_type_array)) {
                m = (int)json_object_array_length(arr);
                for (j = 0; j < m; j++)
                    webd_port_cap_array_add_unique_str(controllers,
                        json_object_get_string(json_object_array_get_idx(arr, j)));
            }
        }
    }

    if (!reason[0])
        reason = poe_seen ? (poe_supported ? "poe_controller_detected_but_runtime_apply_not_integrated" :
                            "no_poe_controller_detected") :
                            "poe_probe_not_returned_by_core";
    if (poe_supported > 0 && supported)
        webd_port_cap_array_add_unique_str(supported, "poe_status_read");
    if (unsupported)
        webd_port_cap_array_add_unique_str(unsupported, poe_supported > 0 ?
                                           "poe_config_apply" : "poe_config");
    json_object_object_add(cap, "poe_probe", json_object_new_boolean(poe_seen > 0));
    json_object_object_add(cap, "poe_probe_source", json_object_new_string("dreamingwrt.physical_port_list.ports[].poe"));
    json_object_object_add(cap, "poe_ports_seen", json_object_new_int(port_count));
    json_object_object_add(cap, "poe_ports_with_probe", json_object_new_int(poe_seen));
    json_object_object_add(cap, "poe_supported", json_object_new_boolean(poe_supported > 0));
    json_object_object_add(cap, "poe_supported_ports", json_object_new_int(poe_supported));
    json_object_object_add(cap, "poe_runtime_read", json_object_new_boolean(poe_runtime_read > 0));
    json_object_object_add(cap, "poe_runtime_apply", json_object_new_boolean(0));
    json_object_object_add(cap, "poe_controller_count", json_object_new_int(controller_count));
    json_object_object_add(cap, "poe_controllers", controllers);
    json_object_object_add(cap, "poe_reason", json_object_new_string(reason));
}

static struct json_object *webd_topology_port_write_capabilities(struct json_object *ports)
{
    struct json_object *cap = json_object_new_object();
    struct json_object *supported = json_object_new_array();
    struct json_object *unsupported = json_object_new_array();

    json_object_array_add(supported, json_object_new_string("enabled"));
    json_object_array_add(supported, json_object_new_string("speed_config"));
    json_object_array_add(supported, json_object_new_string("duplex_config"));
    json_object_array_add(supported, json_object_new_string("autoneg"));
    json_object_array_add(supported, json_object_new_string("vlan_profile_save"));
    json_object_array_add(supported, json_object_new_string("vlan_runtime_apply"));
    json_object_array_add(supported, json_object_new_string("port_reassignment_preview"));
    json_object_array_add(unsupported, json_object_new_string("poe_config"));
    json_object_array_add(unsupported, json_object_new_string("port_reassignment"));
    json_object_array_add(unsupported, json_object_new_string("port_reassignment_apply"));
    json_object_object_add(cap, "read", json_object_new_boolean(1));
    json_object_object_add(cap, "write", json_object_new_boolean(1));
    json_object_object_add(cap, "preview", json_object_new_boolean(1));
    json_object_object_add(cap, "apply", json_object_new_boolean(1));
    json_object_object_add(cap, "requires_confirm", json_object_new_boolean(1));
    json_object_object_add(cap, "port_enable", json_object_new_boolean(1));
    json_object_object_add(cap, "speed_config", json_object_new_boolean(1));
    json_object_object_add(cap, "duplex_config", json_object_new_boolean(1));
    json_object_object_add(cap, "autoneg_config", json_object_new_boolean(1));
    json_object_object_add(cap, "speed_config_persistent", json_object_new_boolean(1));
    json_object_object_add(cap, "duplex_config_persistent", json_object_new_boolean(1));
    json_object_object_add(cap, "post_apply_readback", json_object_new_boolean(1));
    json_object_object_add(cap, "post_apply_verification", json_object_new_boolean(1));
    json_object_object_add(cap, "audit_event_detail", json_object_new_boolean(1));
    json_object_object_add(cap, "vlan_profile_save", json_object_new_boolean(1));
    json_object_object_add(cap, "port_profile_catalog", json_object_new_boolean(1));
    json_object_object_add(cap, "port_profile_endpoint", json_object_new_string("/api/v1/topology/port-profiles"));
    json_object_object_add(cap, "vlan_config", json_object_new_boolean(1));
    json_object_object_add(cap, "vlan_runtime_apply", json_object_new_boolean(1));
    json_object_object_add(cap, "vlan_transaction_preview", json_object_new_boolean(1));
    json_object_object_add(cap, "network_config_snapshot", json_object_new_boolean(1));
    json_object_object_add(cap, "rollback_executor", json_object_new_boolean(1));
    json_object_object_add(cap, "rollback_executor_scope", json_object_new_string("/etc/config/network snapshot restore"));
    json_object_object_add(cap, "reachability_probe", json_object_new_boolean(1));
    json_object_object_add(cap, "reachability_probe_scope", json_object_new_string("local_control_plane_limited"));
    json_object_object_add(cap, "vlan_runtime_probe", json_object_new_boolean(1));
    json_object_object_add(cap, "vlan_runtime_plan_detail", json_object_new_boolean(1));
    json_object_object_add(cap, "network_transaction_dry_run", json_object_new_boolean(1));
    json_object_object_add(cap, "transaction_validate_endpoint",
                           json_object_new_string("/api/v1/topology/node/ports/transaction/validate"));
    json_object_object_add(cap, "transaction_status_endpoint",
                           json_object_new_string("/api/v1/port-manager/status"));
    json_object_object_add(cap, "transaction_list_endpoint",
                           json_object_new_string("/api/v1/port-manager/transactions"));
    json_object_object_add(cap, "transaction_create_endpoint",
                           json_object_new_string("/api/v1/port-manager/transactions"));
    json_object_object_add(cap, "transaction_preview_endpoint",
                           json_object_new_string("/api/v1/port-manager/transactions/preview"));
    json_object_object_add(cap, "transaction_confirm_endpoint",
                           json_object_new_string("/api/v1/port-manager/transactions/{id}/confirm"));
    json_object_object_add(cap, "transaction_rollback_endpoint",
                           json_object_new_string("/api/v1/port-manager/transactions/{id}/rollback"));
    json_object_object_add(cap, "transaction_confirm_live_apply", json_object_new_boolean(1));
    json_object_object_add(cap, "transaction_confirm_behavior",
                           json_object_new_string("vlan_runtime_apply_pending_confirm_or_rollback"));
    json_object_object_add(cap, "dry_run_diff", json_object_new_boolean(1));
    json_object_object_add(cap, "affected_files", json_object_new_boolean(1));
    json_object_object_add(cap, "requires_management_reachability", json_object_new_boolean(1));
    json_object_object_add(cap, "vlan_runtime_reason", json_object_new_string("dsa_bridge_vlan_uci_reload_guarded"));
    json_object_object_add(cap, "poe_config", json_object_new_boolean(0));
    webd_topology_port_poe_cap_summary(cap, ports, supported, unsupported);
    json_object_object_add(cap, "port_reassignment", json_object_new_boolean(0));
    json_object_object_add(cap, "port_reassignment_preview", json_object_new_boolean(1));
    json_object_object_add(cap, "port_reassignment_apply", json_object_new_boolean(0));
    json_object_object_add(cap, "port_reassignment_transaction", json_object_new_boolean(0));
    json_object_object_add(cap, "gateway_port_assignment_atomic_apply", json_object_new_boolean(1));
    json_object_object_add(cap, "gateway_port_assignment_requires_confirm", json_object_new_boolean(1));
    json_object_object_add(cap, "gateway_port_assignment_endpoint",
                           json_object_new_string("/api/v1/network/gateway-ports/apply"));
    json_object_object_add(cap, "port_migration_plan", json_object_new_boolean(1));
    json_object_object_add(cap, "lldp_discovery_read", json_object_new_boolean(1));
    json_object_object_add(cap, "bridge_fdb_read", json_object_new_boolean(1));
    json_object_object_add(cap, "managed_switch_fdb", json_object_new_boolean(0));
    json_object_object_add(cap, "ap_radio_mapping", json_object_new_boolean(0));
    json_object_object_add(cap, "port_alias_write", json_object_new_boolean(1));
    json_object_object_add(cap, "port_display_metadata", json_object_new_boolean(1));
    json_object_object_add(cap, "port_stp_runtime", json_object_new_boolean(1));
    json_object_object_add(cap, "port_column_preferences", json_object_new_boolean(1));
    json_object_object_add(cap, "port_batch_preview", json_object_new_boolean(1));
    json_object_object_add(cap, "port_batch_apply", json_object_new_boolean(1));
    json_object_object_add(cap, "port_batch_atomic", json_object_new_boolean(0));
    json_object_object_add(cap, "port_batch_partial", json_object_new_boolean(1));
    json_object_object_add(cap, "port_batch_max_ports", json_object_new_int(WEBD_PORT_BATCH_MAX));
    json_object_object_add(cap, "port_batch_preview_endpoint",
                           json_object_new_string("/api/v1/topology/node/ports/batch/preview"));
    json_object_object_add(cap, "port_batch_apply_endpoint",
                           json_object_new_string("/api/v1/topology/node/ports/batch/apply"));
    json_object_object_add(cap, "contract_version", json_object_new_int(8));
    json_object_object_add(cap, "supported_writes", supported);
    json_object_object_add(cap, "unsupported_writes", unsupported);
    json_object_object_add(cap, "preview_endpoint", json_object_new_string("/api/v1/topology/node/ports/preview"));
    json_object_object_add(cap, "apply_endpoint", json_object_new_string("/api/v1/topology/node/ports/apply"));
    json_object_object_add(cap, "reason", json_object_new_string("guarded_write_contract; enabled and speed/duplex/autoneg can apply; DSA VLAN/profile can apply through snapshot+UCI+reload+readback+health transaction; PoE and owner migration remain disabled"));
    return cap;
}

static int webd_array_add_unique_str(struct json_object *arr, const char *s)
{
    int i, n;

    if (!arr || !json_object_is_type(arr, json_type_array) || !s || !s[0])
        return 0;
    n = (int)json_object_array_length(arr);
    for (i = 0; i < n; i++) {
        const char *cur = json_object_get_string(json_object_array_get_idx(arr, i));
        if (cur && !strcmp(cur, s))
            return 0;
    }
    json_object_array_add(arr, json_object_new_string(s));
    return 1;
}

static int webd_port_unsupported_detail_exists(struct json_object *arr, const char *field)
{
    int i, n;

    if (!arr || !json_object_is_type(arr, json_type_array) || !field || !field[0])
        return 0;
    n = (int)json_object_array_length(arr);
    for (i = 0; i < n; i++) {
        struct json_object *o = json_object_array_get_idx(arr, i);
        const char *cur = app_nc_json_str(o, "field", "");

        if (!strcmp(cur, field))
            return 1;
    }
    return 0;
}

static void webd_port_plan_add_unsupported_detail(struct json_object *unsupported,
                                                  struct json_object *details,
                                                  const char *field,
                                                  const char *capability,
                                                  const char *reason,
                                                  struct json_object *port)
{
    struct json_object *d;
    struct json_object *caps;

    if (!field || !field[0])
        return;
    webd_array_add_unique_str(unsupported, field);
    if (capability && capability[0] && strcmp(capability, field))
        webd_array_add_unique_str(unsupported, capability);
    if (!details || webd_port_unsupported_detail_exists(details, field))
        return;
    d = json_object_new_object();
    webd_obj_add_str(d, "field", field);
    webd_obj_add_str(d, "capability", capability && capability[0] ? capability : field);
    webd_obj_add_str(d, "reason", reason && reason[0] ? reason : "unsupported");
    webd_obj_add_str(d, "message", "runtime capability may be readable, but persistent port apply is not implemented yet");
    if (port) {
        webd_json_copy_key(d, "ifname", port, "name");
        webd_json_copy_key(d, "speed_mbps", port, "speed_mbps");
        webd_json_copy_key(d, "duplex", port, "duplex");
        webd_json_copy_key(d, "supported_speeds", port, "supported_speeds");
        webd_json_copy_key(d, "supported_duplex", port, "supported_duplex");
        webd_json_copy_key(d, "poe", port, "poe");
        caps = webd_obj_child_obj(port, "capabilities");
        if (caps)
            json_object_object_add(d, "port_capabilities", json_object_get(caps));
    }
    json_object_array_add(details, d);
}

static const char *webd_port_field_capability(const char *field)
{
    if (!field)
        return "";
    if (!strcmp(field, "speed") || !strcmp(field, "speed_mbps") ||
        !strcmp(field, "configured_speed_mbps"))
        return "speed_config";
    if (!strcmp(field, "duplex") || !strcmp(field, "configured_duplex"))
        return "duplex_config";
    if (!strcmp(field, "autoneg") || !strcmp(field, "configured_autoneg"))
        return "autoneg_config";
    if (!strcmp(field, "vlan") || !strcmp(field, "vlan_id") ||
        !strcmp(field, "native_vlan") || !strcmp(field, "tagged_vlans") ||
        !strcmp(field, "profile") || !strcmp(field, "profile_id") ||
        !strcmp(field, "stp"))
        return "vlan_config";
    if (!strcmp(field, "poe") || !strcmp(field, "poe_enabled"))
        return "poe_config";
    if (!strcmp(field, "display_name") || !strcmp(field, "alias") ||
        !strcmp(field, "sort_order"))
        return "display_metadata";
    return field;
}

static int webd_port_plan_field_supported(const char *field)
{
    const char *cap = webd_port_field_capability(field);

    if (!strcmp(cap, "speed_config") ||
        !strcmp(cap, "duplex_config") ||
        !strcmp(cap, "autoneg_config"))
        return 1;
    if (!strcmp(cap, "display_metadata"))
        return 1;
    if (!strcmp(cap, "vlan_config"))
        return 1; /* saved-only in config.db; runtime bridge vlan apply remains pending */
    return 0;
}

static int webd_port_plan_add_unsupported_from_body(struct json_object *body,
                                                    struct json_object *unsupported,
                                                    struct json_object *details,
                                                    struct json_object *port)
{
    static const char *keys[] = {
        "speed", "speed_mbps", "configured_speed_mbps", "duplex",
        "configured_duplex", "autoneg", "configured_autoneg",
        "vlan", "vlan_id", "native_vlan", "tagged_vlans", "poe", "poe_enabled",
        "profile", "profile_id", "stp", "display_name", "alias", "sort_order", NULL
    };
    int i;
    int count = 0;

    for (i = 0; keys[i]; i++) {
        if (app_nc_json_has(body, keys[i])) {
            const char *capability = webd_port_field_capability(keys[i]);
            const char *reason = "persistent_apply_not_implemented";

            count++;
            if (webd_port_plan_field_supported(keys[i]))
                continue;
            if (!strcmp(capability, "poe_config")) {
                struct json_object *poe = webd_obj_child_obj(port, "poe");
                struct json_object *probe = poe ? webd_obj_child_obj(poe, "controller_probe") : NULL;

                reason = app_nc_json_str(poe, "reason", "");
                if (!reason[0])
                    reason = app_nc_json_str(probe, "reason", "");
                if (!reason[0])
                    reason = "poe_probe_not_returned_by_core";
            }
            else if (!strcmp(capability, "vlan_config"))
                reason = "netifd_dsa_bridge_vlan_transaction_pending";
            webd_port_plan_add_unsupported_detail(unsupported, details, keys[i],
                                                  capability, reason, port);
        }
    }
    return count;
}

static struct json_object *webd_physical_port_find(const char *ifname)
{
    struct json_object *upstream = NULL;
    struct json_object *data = NULL;
    struct json_object *ports = NULL;
    struct json_object *found = NULL;
    int i, n;

    upstream = app_ubus_invoke_timeout("physical_port_list", NULL, 2000);
    data = webd_data_or_self_from_jmx_response(upstream);
    ports = webd_obj_child_array(data, "ports");
    if (ports && ifname && ifname[0]) {
        n = (int)json_object_array_length(ports);
        for (i = 0; i < n; i++) {
            struct json_object *p = json_object_array_get_idx(ports, i);

            if (webd_str_eq_nonempty(app_nc_json_str(p, "name", ""), ifname) ||
                webd_str_eq_nonempty(app_nc_json_str(p, "ifname", ""), ifname)) {
                found = json_object_get(p);
                break;
            }
        }
    }
    if (data)
        json_object_put(data);
    if (upstream)
        json_object_put(upstream);
    return found;
}

static void webd_port_plan_fill_request(const struct http_req *req,
                                        struct json_object *body,
                                        char *ifname, size_t ifname_len,
                                        char *target_owner_type, size_t owner_type_len,
                                        char *target_owner_id, size_t owner_id_len,
                                        int *enabled_present,
                                        int *enabled_value)
{
    char buf[128];
    const char *s;

    if (ifname && ifname_len)
        ifname[0] = 0;
    if (target_owner_type && owner_type_len)
        target_owner_type[0] = 0;
    if (target_owner_id && owner_id_len)
        target_owner_id[0] = 0;
    if (enabled_present)
        *enabled_present = 0;
    if (enabled_value)
        *enabled_value = 1;

    if (ifname && !webd_query_get(req ? req->query : "", "ifname", ifname, ifname_len))
        snprintf(ifname, ifname_len, "%s", app_nc_json_str(body, "ifname", ""));
    if (ifname && !ifname[0]) {
        s = app_nc_json_str(body, "port_id", "");
        if (s && s[0] && !strchr(s, ':'))
            snprintf(ifname, ifname_len, "%s", s);
    }
    if (target_owner_type &&
        !webd_query_get(req ? req->query : "", "owner_type", target_owner_type, owner_type_len)) {
        s = app_nc_json_str(body, "target_owner_type",
            app_nc_json_str(body, "owner_type",
            app_nc_json_str(body, "target_role", "")));
        snprintf(target_owner_type, owner_type_len, "%s", s ? s : "");
    }
    if (target_owner_id &&
        !webd_query_get(req ? req->query : "", "owner_id", target_owner_id, owner_id_len)) {
        s = app_nc_json_str(body, "target_owner_id",
            app_nc_json_str(body, "owner_id",
            app_nc_json_str(body, "target_id", "")));
        snprintf(target_owner_id, owner_id_len, "%s", s ? s : "");
    }
    if (enabled_present && enabled_value) {
        if (webd_query_get(req ? req->query : "", "enabled", buf, sizeof(buf))) {
            *enabled_present = 1;
            *enabled_value = (!strcmp(buf, "1") || !strcasecmp(buf, "true") || !strcasecmp(buf, "yes"));
        } else if (app_nc_json_has(body, "enabled")) {
            *enabled_present = 1;
            *enabled_value = app_nc_json_bool(body, "enabled", 1);
        } else if (app_nc_json_has(body, "disabled")) {
            *enabled_present = 1;
            *enabled_value = !app_nc_json_bool(body, "disabled", 0);
        }
    }
}

static void webd_normalize_duplex_value(const char *in, char *out, size_t out_len)
{
    size_t i;

    if (!out || out_len == 0)
        return;
    out[0] = 0;
    if (!in || !in[0])
        return;
    snprintf(out, out_len, "%s", in);
    for (i = 0; out[i]; i++)
        out[i] = (char)tolower((unsigned char)out[i]);
    if (!strncmp(out, "full", 4))
        snprintf(out, out_len, "full");
    else if (!strncmp(out, "half", 4))
        snprintf(out, out_len, "half");
    else
        out[0] = 0;
}

static int webd_port_request_speed(struct json_object *body)
{
    if (app_nc_json_has(body, "speed_mbps"))
        return app_nc_json_int(body, "speed_mbps", 0);
    if (app_nc_json_has(body, "configured_speed_mbps"))
        return app_nc_json_int(body, "configured_speed_mbps", 0);
    if (app_nc_json_has(body, "speed"))
        return app_nc_json_int(body, "speed", 0);
    return 0;
}

static int webd_port_request_autoneg(struct json_object *body, int *present)
{
    if (present)
        *present = 0;
    if (app_nc_json_has(body, "autoneg")) {
        if (present) *present = 1;
        return app_nc_json_bool(body, "autoneg", 1) ? 1 : 0;
    }
    if (app_nc_json_has(body, "configured_autoneg")) {
        if (present) *present = 1;
        return app_nc_json_int(body, "configured_autoneg", -1);
    }
    return -1;
}

static int webd_port_request_tagged_vlans(struct json_object *body, struct json_object **out)
{
    struct json_object *v = NULL;

    if (out)
        *out = NULL;
    if (!json_object_object_get_ex(body, "tagged_vlans", &v) || !v)
        return 0;
    if (!json_object_is_type(v, json_type_array))
        return -1;
    if (out)
        *out = v;
    return 1;
}

struct webd_network_iface_probe {
    int found;
    char id[64];
    char device[128];
    char proto[32];
    char ipaddr[64];
    char gateway[64];
    int username_present;
    int password_present;
    int references_ifname;
};

static int webd_uci_parse_config_line(const char *p,
                                      char *type, size_t type_len,
                                      char *name, size_t name_len)
{
    char t[64] = "";
    char n[128] = "";

    if (!p || strncmp(p, "config ", 7))
        return 0;
    if (sscanf(p, "config %63s '%127[^']'", t, n) < 1 &&
        sscanf(p, "config %63s \"%127[^\"]\"", t, n) < 1 &&
        sscanf(p, "config %63s %127s", t, n) < 1)
        return 0;
    if (type && type_len)
        snprintf(type, type_len, "%s", t);
    if (name && name_len)
        snprintf(name, name_len, "%s", n);
    return 1;
}

static int webd_uci_parse_kv_line(const char *p,
                                  char *directive, size_t directive_len,
                                  char *key, size_t key_len,
                                  char *value, size_t value_len)
{
    char d[16] = "";
    char k[64] = "";
    char v[256] = "";

    if (!p)
        return 0;
    if (sscanf(p, "%15s %63s '%255[^']'", d, k, v) < 3 &&
        sscanf(p, "%15s %63s \"%255[^\"]\"", d, k, v) < 3 &&
        sscanf(p, "%15s %63s %255s", d, k, v) < 3)
        return 0;
    if (strcmp(d, "option") && strcmp(d, "list"))
        return 0;
    if (directive && directive_len)
        snprintf(directive, directive_len, "%s", d);
    if (key && key_len)
        snprintf(key, key_len, "%s", k);
    if (value && value_len)
        snprintf(value, value_len, "%s", v);
    return 1;
}

static void webd_iface_probe_init(struct webd_network_iface_probe *p,
                                  const char *id)
{
    if (!p)
        return;
    memset(p, 0, sizeof(*p));
    snprintf(p->id, sizeof(p->id), "%s", id ? id : "");
}

static void webd_iface_probe_consume_kv(struct webd_network_iface_probe *p,
                                        const char *key,
                                        const char *value,
                                        const char *ifname)
{
    if (!p || !key || !value)
        return;
    p->found = 1;
    if (!strcmp(key, "device") || !strcmp(key, "ifname")) {
        snprintf(p->device, sizeof(p->device), "%s", value);
        if (ifname && ifname[0] && strstr(value, ifname))
            p->references_ifname++;
    } else if (!strcmp(key, "proto")) {
        snprintf(p->proto, sizeof(p->proto), "%s", value);
    } else if (!strcmp(key, "ipaddr")) {
        snprintf(p->ipaddr, sizeof(p->ipaddr), "%s", value);
    } else if (!strcmp(key, "gateway")) {
        snprintf(p->gateway, sizeof(p->gateway), "%s", value);
    } else if (!strcmp(key, "username")) {
        p->username_present = value[0] != 0;
    } else if (!strcmp(key, "password") || !strcmp(key, "key")) {
        p->password_present = value[0] != 0;
    }
}

static struct json_object *webd_iface_probe_json(const struct webd_network_iface_probe *p)
{
    struct json_object *o = json_object_new_object();

    json_object_object_add(o, "id", json_object_new_string(p ? p->id : ""));
    json_object_object_add(o, "found", json_object_new_boolean(p && p->found));
    json_object_object_add(o, "device", json_object_new_string(p ? p->device : ""));
    json_object_object_add(o, "proto", json_object_new_string(p ? p->proto : ""));
    json_object_object_add(o, "ipaddr", json_object_new_string(p ? p->ipaddr : ""));
    json_object_object_add(o, "gateway_present", json_object_new_boolean(p && p->gateway[0]));
    json_object_object_add(o, "username_present", json_object_new_boolean(p && p->username_present));
    json_object_object_add(o, "password_present", json_object_new_boolean(p && p->password_present));
    json_object_object_add(o, "password_redacted", json_object_new_boolean(p && p->password_present));
    json_object_object_add(o, "references_requested_ifname", json_object_new_int(p ? p->references_ifname : 0));
    return o;
}

static int webd_file_writable_parent(const char *path)
{
    char tmp[320];
    char *slash;

    if (!path || !path[0])
        return 0;
    snprintf(tmp, sizeof(tmp), "%s", path);
    slash = strrchr(tmp, '/');
    if (!slash)
        return 0;
    if (slash == tmp)
        slash[1] = '\0';
    else
        *slash = '\0';
    return access(tmp, W_OK) == 0;
}

static const char *webd_bridge_cmd_path(void);

static struct json_object *webd_port_network_transaction_preflight(const char *ifname,
                                                                   const char *bridge_name,
                                                                   const char *from_owner_id,
                                                                   const char *to_owner_id)
{
    struct webd_network_iface_probe from_if;
    struct webd_network_iface_probe to_if;
    struct webd_network_iface_probe lan_if;
    struct json_object *pf = json_object_new_object();
    struct json_object *tools = json_object_new_object();
    struct json_object *bridge = json_object_new_object();
    struct json_object *bridge_ports = json_object_new_array();
    struct json_object *ifaces = json_object_new_object();
    struct json_object *mgmt = json_object_new_object();
    struct json_object *risks = json_object_new_array();
    struct json_object *prereq = json_object_new_object();
    FILE *fp;
    char line[512];
    char current_type[64] = "";
    char current_name[128] = "";
    char current_device_name[128] = "";
    int current_device_is_bridge = 0;
    int bridge_device_found = 0;
    int bridge_type_bridge = 0;
    int bridge_contains_ifname = 0;
    int if_is_lan_bridge_port = 0;
    int if_is_lan_device = 0;
    int from_is_lan = from_owner_id && !strcmp(from_owner_id, "lan");
    int to_is_lan = to_owner_id && !strcmp(to_owner_id, "lan");
    int from_is_wan = from_owner_id && !strncmp(from_owner_id, "wan", 3);
    int to_is_wan = to_owner_id && !strncmp(to_owner_id, "wan", 3);
    int can_snapshot;
    int can_reload;

    if (!ifname)
        ifname = "";
    if (!bridge_name || !bridge_name[0])
        bridge_name = "br-lan";
    webd_iface_probe_init(&from_if, from_owner_id ? from_owner_id : "");
    webd_iface_probe_init(&to_if, to_owner_id ? to_owner_id : "");
    webd_iface_probe_init(&lan_if, "lan");

    fp = fopen("/etc/config/network", "r");
    if (fp) {
        while (fgets(line, sizeof(line), fp)) {
            char *p = line;
            char directive[16], key[64], value[256];

            while (*p && isspace((unsigned char)*p))
                p++;
            if (*p == '#' || !*p)
                continue;
            if (webd_uci_parse_config_line(p, current_type, sizeof(current_type),
                                           current_name, sizeof(current_name))) {
                current_device_name[0] = '\0';
                current_device_is_bridge = 0;
                continue;
            }
            if (!webd_uci_parse_kv_line(p, directive, sizeof(directive),
                                        key, sizeof(key), value, sizeof(value)))
                continue;
            if (!strcmp(current_type, "interface")) {
                if (from_owner_id && from_owner_id[0] && !strcmp(current_name, from_owner_id))
                    webd_iface_probe_consume_kv(&from_if, key, value, ifname);
                if (to_owner_id && to_owner_id[0] && !strcmp(current_name, to_owner_id))
                    webd_iface_probe_consume_kv(&to_if, key, value, ifname);
                if (!strcmp(current_name, "lan"))
                    webd_iface_probe_consume_kv(&lan_if, key, value, ifname);
            } else if (!strcmp(current_type, "device")) {
                if (!strcmp(directive, "option") && !strcmp(key, "name")) {
                    JMX_STRBUF_COPY(current_device_name, value);
                    if (!strcmp(value, bridge_name)) {
                        current_device_is_bridge = 1;
                        bridge_device_found = 1;
                    }
                } else if (!strcmp(directive, "option") && !strcmp(key, "type") &&
                           !strcmp(value, "bridge") && current_device_is_bridge) {
                    bridge_type_bridge = 1;
                } else if (!strcmp(directive, "list") && !strcmp(key, "ports") &&
                           current_device_is_bridge) {
                    webd_array_add_unique_str(bridge_ports, value);
                    if (ifname[0] && !strcmp(value, ifname))
                        bridge_contains_ifname = 1;
                }
            }
        }
        fclose(fp);
    }

    if_is_lan_bridge_port = ifname[0] && bridge_contains_ifname &&
                            (!strcmp(lan_if.device, bridge_name) || !strcmp(bridge_name, "br-lan"));
    if_is_lan_device = ifname[0] && !strcmp(lan_if.device, ifname);
    if (if_is_lan_bridge_port || if_is_lan_device) {
        json_object_array_add(risks, json_object_new_string("requested_port_is_current_management_lan_path"));
    }
    if (from_is_lan && !to_is_lan)
        json_object_array_add(risks, json_object_new_string("migration_removes_port_from_lan_management_side"));
    if ((from_is_wan || to_is_wan) && (from_if.password_present || to_if.password_present))
        json_object_array_add(risks, json_object_new_string("pppoe_or_secret_fields_present_and_redacted"));

    can_snapshot = access("/etc/config/network", R_OK) == 0 &&
                   (access("/tmp", W_OK) == 0 || webd_file_writable_parent("/etc/dreamingwrt/network-backup/network"));
    can_reload = access("/etc/init.d/network", X_OK) == 0 || access("/sbin/ifup", X_OK) == 0;

    json_object_object_add(tools, "uci", json_object_new_boolean(access("/sbin/uci", X_OK) == 0 || access("/usr/sbin/uci", X_OK) == 0));
    json_object_object_add(tools, "ip", json_object_new_boolean(access("/sbin/ip", X_OK) == 0 || access("/usr/sbin/ip", X_OK) == 0));
    json_object_object_add(tools, "ifstatus", json_object_new_boolean(access("/sbin/ifstatus", X_OK) == 0 || access("/usr/sbin/ifstatus", X_OK) == 0));
    json_object_object_add(tools, "network_init", json_object_new_boolean(access("/etc/init.d/network", X_OK) == 0));
    json_object_object_add(tools, "bridge", json_object_new_boolean(webd_bridge_cmd_path()[0] != 0));

    json_object_object_add(bridge, "name", json_object_new_string(bridge_name));
    json_object_object_add(bridge, "found", json_object_new_boolean(bridge_device_found));
    json_object_object_add(bridge, "type_bridge", json_object_new_boolean(bridge_type_bridge));
    json_object_object_add(bridge, "ports", bridge_ports);
    json_object_object_add(bridge, "contains_requested_ifname", json_object_new_boolean(bridge_contains_ifname));

    json_object_object_add(ifaces, "from", webd_iface_probe_json(&from_if));
    json_object_object_add(ifaces, "to", webd_iface_probe_json(&to_if));
    json_object_object_add(ifaces, "lan", webd_iface_probe_json(&lan_if));

    json_object_object_add(mgmt, "lan_ipaddr", json_object_new_string(lan_if.ipaddr));
    json_object_object_add(mgmt, "lan_device", json_object_new_string(lan_if.device));
    json_object_object_add(mgmt, "requested_port_is_lan_bridge_port", json_object_new_boolean(if_is_lan_bridge_port));
    json_object_object_add(mgmt, "requested_port_is_lan_device", json_object_new_boolean(if_is_lan_device));
    json_object_object_add(mgmt, "risk_level",
                           json_object_new_string((if_is_lan_bridge_port || if_is_lan_device || (from_is_lan && !to_is_lan)) ? "high" : "low"));
    json_object_object_add(mgmt, "risk_reasons", risks);

    json_object_object_add(prereq, "can_snapshot_network_config", json_object_new_boolean(can_snapshot));
    json_object_object_add(prereq, "can_reload_netifd", json_object_new_boolean(can_reload));
    json_object_object_add(prereq, "has_uci", json_object_new_boolean(access("/sbin/uci", X_OK) == 0 || access("/usr/sbin/uci", X_OK) == 0));
    json_object_object_add(prereq, "has_reachability_probe", json_object_new_boolean(1));
    json_object_object_add(prereq, "reachability_probe_scope", json_object_new_string("local_control_plane_limited"));
    json_object_object_add(prereq, "has_rollback_executor", json_object_new_boolean(can_snapshot));
    json_object_object_add(prereq, "rollback_executor_scope", json_object_new_string("/etc/config/network snapshot restore"));

    json_object_object_add(pf, "source", json_object_new_string("/etc/config/network + runtime tools"));
    json_object_object_add(pf, "network_config_readable", json_object_new_boolean(fp != NULL || access("/etc/config/network", R_OK) == 0));
    json_object_object_add(pf, "ifname", json_object_new_string(ifname));
    json_object_object_add(pf, "bridge", bridge);
    json_object_object_add(pf, "interfaces", ifaces);
    json_object_object_add(pf, "tools", tools);
    json_object_object_add(pf, "management", mgmt);
    json_object_object_add(pf, "prerequisites", prereq);
    json_object_object_add(pf, "diff_can_be_generated",
                           json_object_new_boolean((fp != NULL || access("/etc/config/network", R_OK) == 0) &&
                                                   (from_if.found || to_if.found || lan_if.found)));
    json_object_object_add(pf, "runtime_apply_supported", json_object_new_boolean(0));
    json_object_object_add(pf, "rollback_executor_available", json_object_new_boolean(can_snapshot));
    json_object_object_add(pf, "reachability_probe_available", json_object_new_boolean(1));
    json_object_object_add(pf, "apply_blocked_by", json_object_new_string("network_mutation_executor_missing"));
    return pf;
}

struct webd_port_bridge_section_ref {
    char section[128];
    int found;
};

static int webd_port_find_bridge_device_section(struct uci_context *ctx,
                                                struct uci_package *pkg,
                                                const char *bridge_name,
                                                struct webd_port_bridge_section_ref *out)
{
    struct uci_element *e;
    int fallback = 0;

    if (out) {
        out->section[0] = '\0';
        out->found = 0;
    }
    if (!ctx || !pkg || !bridge_name || !bridge_name[0] || !out)
        return -1;
    uci_foreach_element(&pkg->sections, e) {
        struct uci_section *s = uci_to_section(e);
        const char *type;
        const char *name;

        if (!s || strcmp(s->type, "device") != 0 || !s->e.name)
            continue;
        type = uci_lookup_option_string(ctx, s, "type");
        name = uci_lookup_option_string(ctx, s, "name");
        if (!name && !fallback) {
            snprintf(out->section, sizeof(out->section), "%s", s->e.name);
            fallback = 1;
        }
        if (name && !strcmp(name, bridge_name)) {
            snprintf(out->section, sizeof(out->section), "%s", s->e.name);
            out->found = 1;
            return 0;
        }
        if (type && !strcmp(type, "bridge") && name && !strcmp(name, bridge_name)) {
            snprintf(out->section, sizeof(out->section), "%s", s->e.name);
            out->found = 1;
            return 0;
        }
    }
    return out->section[0] ? 0 : -1;
}

static int webd_port_uci_set_option_value(struct uci_context *ctx,
                                          const char *pkg,
                                          const char *section,
                                          const char *option,
                                          const char *value,
                                          char *err, size_t err_len)
{
    struct uci_ptr ptr;
    char lookup[512];

    if (!ctx || !webd_port_uci_section_strict_ok(section) ||
        !webd_port_uci_section_strict_ok(option)) {
        if (err && err_len) snprintf(err, err_len, "invalid_uci_section_or_option");
        return -1;
    }
    snprintf(lookup, sizeof(lookup), "%s.%s.%s=%s", pkg, section, option, value ? value : "");
    memset(&ptr, 0, sizeof(ptr));
    if (uci_lookup_ptr(ctx, &ptr, lookup, true) != UCI_OK || uci_set(ctx, &ptr) != UCI_OK) {
        if (err && err_len) snprintf(err, err_len, "uci_set_failed:%s.%s", section, option);
        return -1;
    }
    return 0;
}

static int webd_port_uci_del_option(struct uci_context *ctx,
                                    const char *pkg,
                                    const char *section,
                                    const char *option)
{
    struct uci_ptr ptr;
    char lookup[512];

    if (!ctx || !webd_port_uci_section_strict_ok(section) ||
        !webd_port_uci_section_strict_ok(option))
        return -1;
    snprintf(lookup, sizeof(lookup), "%s.%s.%s", pkg, section, option);
    memset(&ptr, 0, sizeof(ptr));
    if (uci_lookup_ptr(ctx, &ptr, lookup, true) == UCI_OK && ptr.o)
        return uci_delete(ctx, &ptr) == UCI_OK ? 0 : -1;
    return 0;
}

static int webd_port_uci_add_list_value(struct uci_context *ctx,
                                        const char *pkg,
                                        const char *section,
                                        const char *option,
                                        const char *value,
                                        char *err, size_t err_len)
{
    struct uci_ptr ptr;
    char lookup[512];

    if (!ctx || !webd_port_uci_section_strict_ok(section) ||
        !webd_port_uci_section_strict_ok(option) || !value || !value[0]) {
        if (err && err_len) snprintf(err, err_len, "invalid_uci_list_value");
        return -1;
    }
    snprintf(lookup, sizeof(lookup), "%s.%s.%s=%s", pkg, section, option, value);
    memset(&ptr, 0, sizeof(ptr));
    if (uci_lookup_ptr(ctx, &ptr, lookup, true) != UCI_OK ||
        uci_add_list(ctx, &ptr) != UCI_OK) {
        if (err && err_len) snprintf(err, err_len, "uci_add_list_failed:%s.%s", section, option);
        return -1;
    }
    return 0;
}

static struct uci_section *webd_port_find_bridge_vlan_section(struct uci_context *ctx,
                                                             struct uci_package *pkg,
                                                             const char *bridge_name,
                                                             int vlan)
{
    struct uci_element *e;
    char vlan_s[16];

    snprintf(vlan_s, sizeof(vlan_s), "%d", vlan);
    uci_foreach_element(&pkg->sections, e) {
        struct uci_section *s = uci_to_section(e);
        const char *device;
        const char *v;

        if (!s || strcmp(s->type, "bridge-vlan") != 0)
            continue;
        device = uci_lookup_option_string(ctx, s, "device");
        v = uci_lookup_option_string(ctx, s, "vlan");
        if (device && v && !strcmp(device, bridge_name) && !strcmp(v, vlan_s))
            return s;
    }
    return NULL;
}

static int webd_port_ensure_bridge_vlan_section(struct uci_context *ctx,
                                                struct uci_package *pkg,
                                                const char *bridge_name,
                                                int vlan,
                                                char *section, size_t section_len,
                                                char *err, size_t err_len)
{
    struct uci_section *s = webd_port_find_bridge_vlan_section(ctx, pkg, bridge_name, vlan);
    char vlan_s[16];

    if (!ctx || !pkg || !bridge_name || !section || section_len == 0 ||
        !webd_port_vlan_id_ok(vlan, 0)) {
        if (err && err_len) snprintf(err, err_len, "invalid_bridge_vlan_request");
        return -1;
    }
    if (s && s->e.name) {
        snprintf(section, section_len, "%s", s->e.name);
        return 0;
    }
    if (uci_add_section(ctx, pkg, "bridge-vlan", &s) != UCI_OK || !s) {
        if (err && err_len) snprintf(err, err_len, "uci_add_bridge_vlan_failed");
        return -1;
    }
    snprintf(section, section_len, "%s", s->e.name);
    snprintf(vlan_s, sizeof(vlan_s), "%d", vlan);
    if (webd_port_uci_set_option_value(ctx, "network", section, "device", bridge_name, err, err_len) != 0 ||
        webd_port_uci_set_option_value(ctx, "network", section, "vlan", vlan_s, err, err_len) != 0)
        return -1;
    return 0;
}

static int webd_port_section_list_has_value(struct uci_context *ctx,
                                            struct uci_section *s,
                                            const char *option,
                                            const char *value)
{
    struct uci_option *o;
    struct uci_element *e;

    if (!ctx || !s || !option || !value)
        return 0;
    o = uci_lookup_option(ctx, s, option);
    if (!o)
        return 0;
    if (o->type == UCI_TYPE_STRING)
        return o->v.string && !strcmp(o->v.string, value);
    if (o->type != UCI_TYPE_LIST)
        return 0;
    uci_foreach_element(&o->v.list, e) {
        if (e->name && !strcmp(e->name, value))
            return 1;
    }
    return 0;
}

static int webd_port_remove_ifname_from_all_bridge_vlans(struct uci_context *ctx,
                                                         struct uci_package *pkg,
                                                         const char *ifname,
                                                         char *err, size_t err_len)
{
    struct uci_element *e;

    if (!ctx || !pkg || !webd_port_ifname_strict_ok(ifname))
        return -1;
    uci_foreach_element(&pkg->sections, e) {
        struct uci_section *s = uci_to_section(e);
        struct uci_option *o;
        char keep[512][96];
        int keep_n = 0;
        int changed = 0;
        struct uci_element *le;

        if (!s || strcmp(s->type, "bridge-vlan") != 0 || !s->e.name)
            continue;
        o = uci_lookup_option(ctx, s, "ports");
        if (!o)
            continue;
        if (o->type == UCI_TYPE_STRING) {
            const char *v = o->v.string;
            if (v && strncmp(v, ifname, strlen(ifname)) == 0 &&
                (v[strlen(ifname)] == '\0' || v[strlen(ifname)] == ':' || v[strlen(ifname)] == ' ')) {
                changed = 1;
            } else if (v && v[0]) {
                snprintf(keep[keep_n++], sizeof(keep[0]), "%s", v);
            }
        } else if (o->type == UCI_TYPE_LIST) {
            uci_foreach_element(&o->v.list, le) {
                const char *v = le->name;
                if (v && strncmp(v, ifname, strlen(ifname)) == 0 &&
                    (v[strlen(ifname)] == '\0' || v[strlen(ifname)] == ':' || v[strlen(ifname)] == ' '))
                    changed = 1;
                else if (v && v[0] && keep_n < (int)(sizeof(keep) / sizeof(keep[0])))
                    snprintf(keep[keep_n++], sizeof(keep[0]), "%s", v);
            }
        }
        if (changed) {
            int i;
            if (webd_port_uci_del_option(ctx, "network", s->e.name, "ports") != 0) {
                if (err && err_len) snprintf(err, err_len, "uci_delete_ports_failed:%s", s->e.name);
                return -1;
            }
            for (i = 0; i < keep_n; i++) {
                if (webd_port_uci_add_list_value(ctx, "network", s->e.name, "ports",
                                                 keep[i], err, err_len) != 0)
                    return -1;
            }
        }
    }
    return 0;
}

static int webd_port_apply_vlan_uci(struct uci_context *ctx,
                                    struct uci_package *pkg,
                                    const char *ifname,
                                    const char *bridge_name,
                                    int native_vlan,
                                    struct json_object *tagged,
                                    struct json_object *steps,
                                    char *err, size_t err_len)
{
    struct webd_port_bridge_section_ref bridge_ref;
    char port_native[96];
    int i, n = tagged && json_object_is_type(tagged, json_type_array) ?
               (int)json_object_array_length(tagged) : 0;

    if (!webd_port_ifname_strict_ok(ifname) ||
        !webd_port_uci_section_strict_ok(bridge_name)) {
        if (err && err_len) snprintf(err, err_len, "invalid_ifname_or_bridge");
        return -1;
    }
    if (!webd_port_vlan_id_ok(native_vlan, 1) ||
        !webd_port_tagged_vlans_strict_ok(tagged, err, err_len))
        return -1;
    if (webd_port_find_bridge_device_section(ctx, pkg, bridge_name, &bridge_ref) != 0 ||
        !bridge_ref.found) {
        if (err && err_len) snprintf(err, err_len, "bridge_device_section_not_found");
        return -1;
    }
    if (webd_port_uci_set_option_value(ctx, "network", bridge_ref.section,
                                       "vlan_filtering", "1", err, err_len) != 0)
        return -1;
    json_object_array_add(steps, json_object_new_string("set bridge vlan_filtering=1"));
    if (webd_port_remove_ifname_from_all_bridge_vlans(ctx, pkg, ifname,
                                                      err, err_len) != 0)
        return -1;
    json_object_array_add(steps, json_object_new_string("removed requested port from existing bridge-vlan memberships"));

    snprintf(port_native, sizeof(port_native), "%s:u*", ifname);
    {
        char section[128];
        if (webd_port_ensure_bridge_vlan_section(ctx, pkg, bridge_name, native_vlan,
                                                 section, sizeof(section), err, err_len) != 0)
            return -1;
        if (!webd_port_section_list_has_value(ctx, uci_lookup_section(ctx, pkg, section),
                                              "ports", port_native) &&
            webd_port_uci_add_list_value(ctx, "network", section, "ports",
                                         port_native, err, err_len) != 0)
            return -1;
    }
    json_object_array_add(steps, json_object_new_string("set native VLAN bridge-vlan membership"));
    for (i = 0; i < n; i++) {
        int vlan = json_object_get_int(json_object_array_get_idx(tagged, i));
        char section[128];
        char port_tagged[96];

        if (vlan == native_vlan)
            continue;
        if (!webd_port_vlan_id_ok(vlan, 0)) {
            if (err && err_len) snprintf(err, err_len, "invalid_tagged_vlan_%d", vlan);
            return -1;
        }
        snprintf(port_tagged, sizeof(port_tagged), "%s:t", ifname);
        if (webd_port_ensure_bridge_vlan_section(ctx, pkg, bridge_name, vlan,
                                                 section, sizeof(section), err, err_len) != 0)
            return -1;
        if (!webd_port_section_list_has_value(ctx, uci_lookup_section(ctx, pkg, section),
                                              "ports", port_tagged) &&
            webd_port_uci_add_list_value(ctx, "network", section, "ports",
                                         port_tagged, err, err_len) != 0)
            return -1;
    }
    if (n > 0)
        json_object_array_add(steps, json_object_new_string("set tagged VLAN bridge-vlan memberships"));
    return 0;
}

static int webd_port_manager_extract_vlan_target(struct json_object *changes,
                                                 char *ifname, size_t ifname_len,
                                                 char *bridge, size_t bridge_len,
                                                 int *native_vlan,
                                                 struct json_object **tagged,
                                                 char *err, size_t err_len)
{
    struct json_object *req = webd_obj_child_obj(changes, "request");
    struct json_object *plan = webd_obj_child_obj(changes, "plan");
    struct json_object *vp = plan ? webd_obj_child_obj(plan, "vlan_runtime_plan") : NULL;
    struct json_object *effective = NULL;
    struct json_object *arr = NULL;
    const char *ifn = app_nc_json_str(changes, "ifname", app_nc_json_str(plan, "ifname", ""));
    const char *br = app_nc_json_str(req, "bridge", app_nc_json_str(req, "bridge_name",
                                app_nc_json_str(vp, "bridge", "br-lan")));
    int native = app_nc_json_int(req, "native_vlan",
                 app_nc_json_int(req, "vlan_id", app_nc_json_int(vp, "native_vlan", 1)));

    if (err && err_len)
        err[0] = '\0';
    if (ifname && ifname_len)
        snprintf(ifname, ifname_len, "%s", ifn ? ifn : "");
    if (bridge && bridge_len)
        snprintf(bridge, bridge_len, "%s", (br && br[0]) ? br : "br-lan");
    if (!webd_port_ifname_strict_ok(ifn)) {
        if (err && err_len) snprintf(err, err_len, "invalid_ifname");
        return -1;
    }
    if (!webd_port_uci_section_strict_ok((br && br[0]) ? br : "br-lan")) {
        if (err && err_len) snprintf(err, err_len, "invalid_bridge_name");
        return -1;
    }
    if (!webd_port_vlan_id_ok(native, 0)) {
        if (err && err_len) snprintf(err, err_len, "invalid_native_vlan");
        return -1;
    }
    if (req)
        effective = webd_port_effective_vlan_target(req, NULL);
    if (effective) {
        native = app_nc_json_int(effective, "native_vlan", native);
        arr = webd_obj_child_array(effective, "tagged_vlans");
        if (arr)
            arr = json_object_get(arr);
        json_object_put(effective);
    }
    if (!arr && vp) {
        arr = webd_obj_child_array(vp, "tagged_vlans");
        if (arr)
            arr = json_object_get(arr);
    }
    if (!webd_port_tagged_vlans_strict_ok(arr, err, err_len))
        return -1;
    if (native <= 0) {
        if (err && err_len) snprintf(err, err_len, "native_vlan_required_for_runtime_apply");
        return -1;
    }
    if (native_vlan)
        *native_vlan = native;
    if (tagged)
        *tagged = arr;
    else if (arr)
        json_object_put(arr);
    return 0;
}

int webd_port_manager_changes_need_vlan_runtime(struct json_object *changes)
{
    struct json_object *plan = webd_obj_child_obj(changes, "plan");

    return changes && plan && app_nc_json_bool(plan, "vlan_profile_present", 0) &&
           !app_nc_json_bool(plan, "owner_migration_requested", 0);
}

struct json_object *webd_port_manager_apply_network_transaction(struct json_object *changes,
                                                                       const char *snapshot_path,
                                                                       int dry_run)
{
    struct json_object *resp = json_object_new_object();
    struct json_object *steps = json_object_new_array();
    struct json_object *warnings = json_object_new_array();
    struct json_object *cap = json_object_new_object();
    struct json_object *health = NULL;
    struct json_object *rb = json_object_new_object();
    struct uci_context *ctx = NULL;
    struct uci_package *pkg = NULL;
    struct json_object *tagged = NULL;
    char ifname[IFNAMSIZ] = "";
    char bridge[64] = "br-lan";
    char err[192] = "";
    char restore_err[192] = "";
    int native_vlan = 0;
    int ok = 0;
    int rollback_applied = 0;

    json_object_object_add(cap, "vlan_runtime_apply", json_object_new_boolean(1));
    json_object_object_add(cap, "poe_runtime_apply", json_object_new_boolean(0));
    json_object_object_add(cap, "port_migration_apply", json_object_new_boolean(0));
    json_object_object_add(cap, "requires_dsa_bridge", json_object_new_boolean(1));

    if (webd_port_manager_extract_vlan_target(changes, ifname, sizeof(ifname),
                                              bridge, sizeof(bridge), &native_vlan,
                                              &tagged, err, sizeof(err)) != 0)
        goto fail;
    if (dry_run) {
        json_object_object_add(resp, "ok", json_object_new_boolean(1));
        json_object_object_add(resp, "dry_run", json_object_new_boolean(1));
        json_object_object_add(resp, "applied", json_object_new_boolean(0));
        json_object_object_add(resp, "ifname", json_object_new_string(ifname));
        json_object_object_add(resp, "bridge", json_object_new_string(bridge));
        json_object_object_add(resp, "native_vlan", json_object_new_int(native_vlan));
        json_object_object_add(resp, "tagged_vlans", tagged ? json_object_get(tagged) : json_object_new_array());
        json_object_object_add(resp, "capability", cap);
        json_object_object_add(resp, "steps", steps);
        json_object_object_add(resp, "warnings", warnings);
        if (tagged)
            json_object_put(tagged);
        return resp;
    }
    {
        char p[256];
        snprintf(p, sizeof(p), "/sys/class/net/%s/brport", ifname);
        if (access(p, F_OK) != 0) {
            snprintf(err, sizeof(err), "capability_missing:not_bridge_port");
            goto fail;
        }
        snprintf(p, sizeof(p), "/sys/class/net/%s/bridge", bridge);
        if (access(p, F_OK) != 0) {
            snprintf(err, sizeof(err), "capability_missing:bridge_not_found");
            goto fail;
        }
        snprintf(p, sizeof(p), "/sys/class/net/%s/dsa", ifname);
        if (access(p, F_OK) != 0) {
            char phys[128] = "";
            snprintf(p, sizeof(p), "/sys/class/net/%s/phys_port_name", ifname);
            if (webd_file_read_first_line(p, phys, sizeof(phys)) != 0 || !phys[0]) {
                snprintf(err, sizeof(err), "capability_missing:not_dsa_or_no_phys_port_name");
                goto fail;
            }
        }
    }
    ctx = uci_alloc_context();
    if (!ctx) {
        snprintf(err, sizeof(err), "uci_context_alloc_failed");
        goto fail;
    }
    if (uci_load(ctx, "network", &pkg) != UCI_OK || !pkg) {
        snprintf(err, sizeof(err), "uci_load_network_failed");
        goto fail;
    }
    if (webd_port_apply_vlan_uci(ctx, pkg, ifname, bridge, native_vlan,
                                 tagged, steps, err, sizeof(err)) != 0)
        goto fail;
    if (uci_commit(ctx, &pkg, 0) != UCI_OK) {
        snprintf(err, sizeof(err), "uci_commit_network_failed");
        goto fail;
    }
    json_object_array_add(steps, json_object_new_string("committed /etc/config/network"));
    if (webd_network_reload_runtime(err, sizeof(err)) != 0)
        goto fail_restore;
    json_object_array_add(steps, json_object_new_string("reloaded network"));
    health = webd_network_local_reachability_probe();
    if (!app_nc_json_bool(health, "loopback_api_ok", 0) ||
        !app_nc_json_bool(health, "lan_status_ok", 0)) {
        snprintf(err, sizeof(err), "management_reachability_probe_failed");
        goto fail_restore;
    }
    if (!webd_port_bridge_vlan_readback(bridge, ifname, native_vlan, tagged, rb)) {
        snprintf(err, sizeof(err), "bridge_vlan_readback_failed");
        goto fail_restore;
    }
    ok = 1;
    goto out;

fail_restore:
    if (snapshot_path && snapshot_path[0] &&
        webd_network_config_restore(snapshot_path, restore_err, sizeof(restore_err)) == 0) {
        char reload_err[160] = "";
        if (webd_network_reload_runtime(reload_err, sizeof(reload_err)) == 0)
            rollback_applied = 1;
        else
            snprintf(restore_err, sizeof(restore_err),
                     "rollback_reload_failed:%s", reload_err);
    }
    goto out;
fail:
    goto out;
out:
    if (ctx)
        uci_free_context(ctx);
    json_object_object_add(resp, "ok", json_object_new_boolean(ok));
    json_object_object_add(resp, "dry_run", json_object_new_boolean(0));
    json_object_object_add(resp, "applied", json_object_new_boolean(ok));
    json_object_object_add(resp, "ifname", json_object_new_string(ifname));
    json_object_object_add(resp, "bridge", json_object_new_string(bridge));
    json_object_object_add(resp, "native_vlan", json_object_new_int(native_vlan));
    json_object_object_add(resp, "tagged_vlans", tagged ? json_object_get(tagged) : json_object_new_array());
    json_object_object_add(resp, "capability", cap);
    json_object_object_add(resp, "steps", steps);
    json_object_object_add(resp, "warnings", warnings);
    json_object_object_add(resp, "health", health ? health : webd_network_local_reachability_probe());
    json_object_object_add(resp, "bridge_vlan_readback", rb);
    json_object_object_add(resp, "rollback_applied", json_object_new_boolean(rollback_applied));
    json_object_object_add(resp, "rollback_source", json_object_new_string(snapshot_path ? snapshot_path : ""));
    if (!ok)
        json_object_object_add(resp, "error", json_object_new_string(err[0] ? err : "network_transaction_failed"));
    if (restore_err[0])
        json_object_object_add(resp, "rollback_error", json_object_new_string(restore_err));
    if (tagged)
        json_object_put(tagged);
    return resp;
}

static void webd_port_copy_readback_config(struct json_object *dst,
                                           struct json_object *port)
{
    struct json_object *cfg = webd_obj_child_obj(port, "config");

    if (!dst)
        return;
    if (!port) {
        json_object_object_add(dst, "found", json_object_new_boolean(0));
        return;
    }
    json_object_object_add(dst, "found", json_object_new_boolean(1));
    webd_json_copy_key(dst, "ifname", port, "ifname");
    webd_json_copy_key(dst, "name", port, "name");
    webd_json_copy_key(dst, "owner_type", port, "owner_type");
    webd_json_copy_key(dst, "owner_id", port, "owner_id");
    webd_json_copy_key(dst, "status", port, "status");
    webd_json_copy_key(dst, "speed_mbps", port, "speed_mbps");
    webd_json_copy_key(dst, "duplex", port, "duplex");
    webd_json_copy_key(dst, "autoneg", port, "autoneg");
    webd_json_copy_key(dst, "configured_speed_mbps", port, "configured_speed_mbps");
    webd_json_copy_key(dst, "configured_duplex", port, "configured_duplex");
    webd_json_copy_key(dst, "configured_autoneg", port, "configured_autoneg");
    webd_json_copy_key(dst, "profile_id", port, "profile_id");
    webd_json_copy_key(dst, "native_vlan", port, "native_vlan");
    webd_json_copy_key(dst, "tagged_vlans", port, "tagged_vlans");
    webd_json_copy_key(dst, "display_name", port, "display_name");
    webd_json_copy_key(dst, "alias", port, "alias");
    webd_json_copy_key(dst, "sort_order", port, "sort_order");
    if (cfg)
        json_object_object_add(dst, "config", json_object_get(cfg));
}

static struct json_object *webd_port_post_apply_readback(const char *ifname,
                                                         int speed_present,
                                                         int duplex_present,
                                                         int autoneg_present,
                                                         int vlan_profile_present,
                                                         int display_metadata_present)
{
    struct json_object *rb = json_object_new_object();
    struct json_object *checks = json_object_new_object();
    struct json_object *warnings = json_object_new_array();
    struct json_object *fresh = NULL;
    char duplex_norm[16] = "";
    int ok = 1;

    json_object_object_add(rb, "supported", json_object_new_boolean(1));
    json_object_object_add(rb, "source", json_object_new_string("dreamingwrt.physical_port_list"));
    json_object_object_add(rb, "ifname", json_object_new_string(ifname ? ifname : ""));
    fresh = webd_physical_port_find(ifname);
    if (!fresh) {
        json_object_object_add(rb, "ok", json_object_new_boolean(0));
        json_object_object_add(rb, "found", json_object_new_boolean(0));
        json_object_object_add(rb, "reason", json_object_new_string("post_apply_port_readback_missing"));
        json_object_object_add(rb, "checks", checks);
        json_object_object_add(rb, "warnings", warnings);
        return rb;
    }

    webd_port_copy_readback_config(rb, fresh);
    if (speed_present) {
        int configured = app_nc_json_int(fresh, "configured_speed_mbps", 0);
        int runtime = app_nc_json_int(fresh, "speed_mbps", 0);

        json_object_object_add(checks, "speed_config_readback", json_object_new_boolean(configured > 0));
        json_object_object_add(checks, "speed_runtime_visible", json_object_new_boolean(runtime > 0));
        if (configured <= 0) {
            ok = 0;
            json_object_array_add(warnings, json_object_new_string("speed_config_not_visible_after_apply"));
        }
    }
    if (duplex_present) {
        webd_normalize_duplex_value(app_nc_json_str(fresh, "configured_duplex", ""), duplex_norm, sizeof(duplex_norm));
        json_object_object_add(checks, "duplex_config_readback", json_object_new_boolean(duplex_norm[0] != 0));
        if (!duplex_norm[0]) {
            ok = 0;
            json_object_array_add(warnings, json_object_new_string("duplex_config_not_visible_after_apply"));
        }
    }
    if (autoneg_present) {
        int configured = app_nc_json_int(fresh, "configured_autoneg", -1);

        json_object_object_add(checks, "autoneg_config_readback", json_object_new_boolean(configured >= 0));
        if (configured < 0) {
            ok = 0;
            json_object_array_add(warnings, json_object_new_string("autoneg_config_not_visible_after_apply"));
        }
    }
    if (vlan_profile_present) {
        const char *profile = app_nc_json_str(fresh, "profile_id", "");
        struct json_object *cfg = webd_obj_child_obj(fresh, "config");

        json_object_object_add(checks, "vlan_profile_saved", json_object_new_boolean(profile[0] != 0 || cfg != NULL));
        json_object_object_add(checks, "vlan_runtime_apply", json_object_new_boolean(0));
        json_object_object_add(checks, "vlan_runtime_reason",
                               json_object_new_string("netifd_dsa_bridge_vlan_transaction_pending"));
        if (!profile[0] && !cfg) {
            ok = 0;
            json_object_array_add(warnings, json_object_new_string("vlan_profile_config_not_visible_after_apply"));
        }
    }
    if (display_metadata_present) {
        struct json_object *cfg = webd_obj_child_obj(fresh, "config");
        int visible = app_nc_json_has(fresh, "display_name") &&
                      app_nc_json_has(fresh, "sort_order") && cfg != NULL;
        json_object_object_add(checks, "display_metadata_readback", json_object_new_boolean(visible));
        if (!visible) {
            ok = 0;
            json_object_array_add(warnings, json_object_new_string("display_metadata_not_visible_after_apply"));
        }
    }
    json_object_object_add(rb, "ok", json_object_new_boolean(ok));
    json_object_object_add(rb, "verified", json_object_new_boolean(ok));
    json_object_object_add(rb, "checks", checks);
    json_object_object_add(rb, "warnings", warnings);
    json_object_object_add(rb, "reason", json_object_new_string(ok ? "post_apply_readback_ok" : "post_apply_readback_degraded"));
    json_object_put(fresh);
    return rb;
}

static void webd_port_plan_add_supported_ops(struct json_object *plan, struct json_object *body,
                                             struct json_object *port,
                                             struct json_object *warnings,
                                             int *supported_count,
                                             int *speed_present,
                                             int *duplex_present,
                                             int *autoneg_present,
                                             int *vlan_profile_present,
                                             int *display_metadata_present)
{
    struct json_object *ops = json_object_new_array();
    struct json_object *supported_speeds = webd_obj_child_array(port, "supported_speeds");
    struct json_object *supported_duplex = webd_obj_child_array(port, "supported_duplex");
    struct json_object *tagged = NULL;
    char duplex[16] = "";
    int speed = webd_port_request_speed(body);
    int an_present = 0;
    int autoneg = webd_port_request_autoneg(body, &an_present);
    int native_vlan = app_nc_json_int(body, "native_vlan", app_nc_json_int(body, "vlan_id", 0));
    const char *duplex_raw = app_nc_json_str(body, "duplex", app_nc_json_str(body, "configured_duplex", ""));
    const char *profile_id = app_nc_json_str(body, "profile_id", app_nc_json_str(body, "profile", ""));
    int tagged_present = webd_port_request_tagged_vlans(body, &tagged);
    int native_vlan_present = app_nc_json_has(body, "native_vlan") || app_nc_json_has(body, "vlan_id");
    int profile_present = app_nc_json_has(body, "profile_id") || app_nc_json_has(body, "profile");
    int name_present = app_nc_json_has(body, "display_name") || app_nc_json_has(body, "alias");
    int order_present = app_nc_json_has(body, "sort_order");

    if (supported_count) *supported_count = 0;
    if (speed_present) *speed_present = 0;
    if (duplex_present) *duplex_present = 0;
    if (autoneg_present) *autoneg_present = 0;
    if (vlan_profile_present) *vlan_profile_present = 0;
    if (display_metadata_present) *display_metadata_present = 0;
    if (duplex_raw && duplex_raw[0])
        webd_normalize_duplex_value(duplex_raw, duplex, sizeof(duplex));
    if (speed > 0) {
        struct json_object *op = json_object_new_object();
        json_object_object_add(op, "field", json_object_new_string("speed_mbps"));
        json_object_object_add(op, "capability", json_object_new_string("speed_config"));
        json_object_object_add(op, "value", json_object_new_int(speed));
        json_object_object_add(op, "runtime_apply", json_object_new_boolean(1));
        json_object_object_add(op, "persistent", json_object_new_boolean(1));
        if (supported_speeds && json_object_array_length(supported_speeds) > 0 &&
            !webd_json_array_contains_int_value(supported_speeds, speed)) {
            json_object_object_add(op, "warning", json_object_new_string("speed_not_in_supported_speeds"));
            json_object_array_add(warnings, json_object_new_string("requested_speed_not_advertised_by_ethtool"));
        }
        json_object_array_add(ops, op);
        if (supported_count) (*supported_count)++;
        if (speed_present) *speed_present = 1;
    }
    if (duplex_raw && duplex_raw[0]) {
        struct json_object *op = json_object_new_object();
        json_object_object_add(op, "field", json_object_new_string("duplex"));
        json_object_object_add(op, "capability", json_object_new_string("duplex_config"));
        json_object_object_add(op, "value", json_object_new_string(duplex));
        json_object_object_add(op, "runtime_apply", json_object_new_boolean(1));
        json_object_object_add(op, "persistent", json_object_new_boolean(1));
        if (!duplex[0]) {
            json_object_object_add(op, "warning", json_object_new_string("invalid_duplex_value"));
            json_object_array_add(warnings, json_object_new_string("invalid_duplex_value; allowed full/half"));
        } else if (supported_duplex && json_object_array_length(supported_duplex) > 0 &&
                   !webd_json_array_contains_string_value(supported_duplex, duplex)) {
            json_object_object_add(op, "warning", json_object_new_string("duplex_not_in_supported_duplex"));
            json_object_array_add(warnings, json_object_new_string("requested_duplex_not_advertised_by_ethtool"));
        }
        json_object_array_add(ops, op);
        if (supported_count) (*supported_count)++;
        if (duplex_present) *duplex_present = 1;
    }
    if (an_present) {
        struct json_object *op = json_object_new_object();
        json_object_object_add(op, "field", json_object_new_string("autoneg"));
        json_object_object_add(op, "capability", json_object_new_string("autoneg_config"));
        json_object_object_add(op, "value", autoneg < 0 ? json_object_new_null() : json_object_new_boolean(autoneg));
        json_object_object_add(op, "runtime_apply", json_object_new_boolean(1));
        json_object_object_add(op, "persistent", json_object_new_boolean(1));
        json_object_array_add(ops, op);
        if (supported_count) (*supported_count)++;
        if (autoneg_present) *autoneg_present = 1;
    }
    if (native_vlan_present || profile_present || tagged_present > 0) {
        struct json_object *op = json_object_new_object();
        json_object_object_add(op, "field", json_object_new_string("vlan_profile"));
        json_object_object_add(op, "capability", json_object_new_string("vlan_profile_save"));
        json_object_object_add(op, "native_vlan_present", json_object_new_boolean(native_vlan_present));
        json_object_object_add(op, "native_vlan", json_object_new_int(native_vlan));
        json_object_object_add(op, "profile_present", json_object_new_boolean(profile_present));
        json_object_object_add(op, "profile_id", json_object_new_string(profile_id ? profile_id : ""));
        json_object_object_add(op, "tagged_vlans_present", json_object_new_boolean(tagged_present > 0));
        if (tagged)
            json_object_object_add(op, "tagged_vlans", json_object_get(tagged));
        else
            json_object_object_add(op, "tagged_vlans", json_object_new_array());
        json_object_object_add(op, "persistent", json_object_new_boolean(1));
        json_object_object_add(op, "runtime_apply", json_object_new_boolean(1));
        json_object_object_add(op, "reason", json_object_new_string("dsa_bridge_vlan_uci_reload_guarded"));
        json_object_array_add(ops, op);
        if (supported_count) (*supported_count)++;
        if (vlan_profile_present) *vlan_profile_present = 1;
        json_object_array_add(warnings, json_object_new_string("vlan_profile_requires_guarded_runtime_transaction"));
    }
    if (name_present || order_present) {
        struct json_object *op = json_object_new_object();
        const char *name = app_nc_json_str(body, "display_name", app_nc_json_str(body, "alias", ""));
        int order = app_nc_json_int(body, "sort_order", 0);

        json_object_object_add(op, "field", json_object_new_string("display_metadata"));
        json_object_object_add(op, "capability", json_object_new_string("display_metadata"));
        json_object_object_add(op, "display_name_present", json_object_new_boolean(name_present));
        json_object_object_add(op, "display_name", json_object_new_string(name));
        json_object_object_add(op, "sort_order_present", json_object_new_boolean(order_present));
        json_object_object_add(op, "sort_order", json_object_new_int(order));
        json_object_object_add(op, "persistent", json_object_new_boolean(1));
        json_object_object_add(op, "runtime_apply", json_object_new_boolean(0));
        json_object_array_add(ops, op);
        if (supported_count) (*supported_count)++;
        if (display_metadata_present) *display_metadata_present = 1;
    }
    json_object_object_add(plan, "supported_operations", ops);
}

static void webd_port_plan_add_unique_str(struct json_object *arr, const char *value)
{
    if (!arr || !value || !value[0])
        return;
    webd_array_add_unique_str(arr, value);
}

static int webd_file_read_first_line(const char *path, char *out, size_t out_len)
{
    FILE *fp;

    if (out && out_len)
        out[0] = '\0';
    if (!path || !out || out_len == 0)
        return -1;
    fp = fopen(path, "r");
    if (!fp)
        return -1;
    if (!fgets(out, out_len, fp)) {
        fclose(fp);
        out[0] = '\0';
        return -1;
    }
    fclose(fp);
    out[strcspn(out, "\r\n")] = '\0';
    return 0;
}

static int webd_dir_has_entries(const char *path)
{
    DIR *dir;
    struct dirent *de;
    int count = 0;

    dir = opendir(path);
    if (!dir)
        return 0;
    while ((de = readdir(dir)) != NULL) {
        if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
            continue;
        count++;
        break;
    }
    closedir(dir);
    return count > 0;
}

static const char *webd_bridge_cmd_path(void)
{
    static const char *paths[] = {
        "/sbin/bridge",
        "/usr/sbin/bridge",
        "/bin/bridge",
        "/usr/bin/bridge",
        NULL
    };

    for (int i = 0; paths[i]; i++) {
        if (access(paths[i], X_OK) == 0)
            return paths[i];
    }
    return "";
}

static int webd_run_argv_capture(const char *const argv[],
                                 char *out, size_t out_len,
                                 int timeout_ms)
{
    int pipefd[2] = {-1, -1};
    pid_t pid;
    int status = 0;
    int elapsed = 0;
    int child_done = 0;
    size_t used = 0;

    if (out && out_len)
        out[0] = '\0';
    if (!argv || !argv[0])
        return -1;
    if (pipe(pipefd) != 0)
        return -1;
    pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }
    if (pid == 0) {
        int devnull = open("/dev/null", O_RDONLY);

        if (devnull >= 0) {
            dup2(devnull, STDIN_FILENO);
            close(devnull);
        }
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[0]);
        close(pipefd[1]);
        execv(argv[0], (char * const *)argv);
        _exit(127);
    }
    close(pipefd[1]);
    pipefd[1] = -1;
    fcntl(pipefd[0], F_SETFL, fcntl(pipefd[0], F_GETFL, 0) | O_NONBLOCK);
    if (timeout_ms <= 0)
        timeout_ms = 3000;
    while (!child_done || pipefd[0] >= 0) {
        char buf[512];
        ssize_t n;

        if (!child_done) {
            pid_t r = waitpid(pid, &status, WNOHANG);
            if (r == pid)
                child_done = 1;
            else if (r < 0 && errno != EINTR)
                child_done = 1;
        }
        n = pipefd[0] >= 0 ? read(pipefd[0], buf, sizeof(buf)) : 0;
        if (n > 0) {
            if (out && out_len && used + 1 < out_len) {
                size_t copy = (size_t)n;
                if (copy > out_len - used - 1)
                    copy = out_len - used - 1;
                memcpy(out + used, buf, copy);
                used += copy;
                out[used] = '\0';
            }
        } else if (n == 0 && child_done) {
            close(pipefd[0]);
            pipefd[0] = -1;
            break;
        } else if (n < 0 && errno != EAGAIN && errno != EINTR) {
            close(pipefd[0]);
            pipefd[0] = -1;
            break;
        }
        if (!child_done) {
            usleep(100000);
            elapsed += 100;
            if (elapsed >= timeout_ms) {
                kill(pid, SIGKILL);
                waitpid(pid, &status, 0);
                if (pipefd[0] >= 0)
                    close(pipefd[0]);
                if (out && out_len && used + 16 < out_len)
                    snprintf(out + used, out_len - used, "\nTIMEOUT");
                return -2;
            }
        } else if (n < 0 && (errno == EAGAIN || errno == EINTR)) {
            usleep(20000);
        }
    }
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static int webd_port_bridge_vlan_readback(const char *bridge_name,
                                          const char *ifname,
                                          int native_vlan,
                                          struct json_object *tagged,
                                          struct json_object *rb)
{
    const char *bridge = webd_bridge_cmd_path();
    const char *argv[] = { NULL, "vlan", "show", "dev", NULL, NULL };
    char out[8192];
    int rc;
    int native_ok = native_vlan <= 0 ? 1 : 0;
    int tagged_ok = 1;
    int i, n = tagged && json_object_is_type(tagged, json_type_array) ?
               (int)json_object_array_length(tagged) : 0;

    if (!rb)
        return 0;
    json_object_object_add(rb, "source", json_object_new_string("bridge vlan show dev"));
    if (!bridge[0] || !ifname || !ifname[0]) {
        json_object_object_add(rb, "ok", json_object_new_boolean(0));
        json_object_object_add(rb, "reason", json_object_new_string(!bridge[0] ? "bridge_command_unavailable" : "invalid_ifname"));
        return 0;
    }
    argv[0] = bridge;
    argv[4] = ifname;
    rc = webd_run_argv_capture(argv, out, sizeof(out), 3000);
    json_object_object_add(rb, "command_rc", json_object_new_int(rc));
    json_object_object_add(rb, "ifname", json_object_new_string(ifname));
    json_object_object_add(rb, "bridge", json_object_new_string(bridge_name ? bridge_name : ""));
    json_object_object_add(rb, "raw", json_object_new_string(out));
    if (rc != 0) {
        json_object_object_add(rb, "ok", json_object_new_boolean(0));
        json_object_object_add(rb, "reason", json_object_new_string("bridge_vlan_show_failed"));
        return 0;
    }
    if (native_vlan > 0) {
        native_ok = webd_text_has_vlan_token(out, native_vlan) &&
                    (strstr(out, "PVID") || strstr(out, "Egress Untagged") ||
                     strstr(out, "untagged"));
    }
    for (i = 0; i < n; i++) {
        int vlan = json_object_get_int(json_object_array_get_idx(tagged, i));
        if (vlan <= 0)
            continue;
        if (!webd_text_has_vlan_token(out, vlan))
            tagged_ok = 0;
    }
    json_object_object_add(rb, "native_vlan_ok", json_object_new_boolean(native_ok));
    json_object_object_add(rb, "tagged_vlans_ok", json_object_new_boolean(tagged_ok));
    json_object_object_add(rb, "ok", json_object_new_boolean(native_ok && tagged_ok));
    json_object_object_add(rb, "reason", json_object_new_string((native_ok && tagged_ok) ?
                           "bridge_vlan_readback_ok" : "bridge_vlan_membership_mismatch"));
    return native_ok && tagged_ok;
}

static int webd_text_has_vlan_token(const char *text, int vlan)
{
    const char *p = text;

    if (!text || vlan <= 0)
        return 0;
    while (*p) {
        char *end = NULL;
        long v;

        while (*p && !isdigit((unsigned char)*p))
            p++;
        if (!*p)
            break;
        errno = 0;
        v = strtol(p, &end, 10);
        if (!errno && end != p && v == vlan)
            return 1;
        p = end && end > p ? end : p + 1;
    }
    return 0;
}

static void webd_port_dry_run_add_change(struct json_object *changes,
                                         const char *action,
                                         const char *target,
                                         const char *before,
                                         const char *after,
                                         const char *reason,
                                         int runtime,
                                         int persistent)
{
    struct json_object *c;

    if (!changes || !json_object_is_type(changes, json_type_array))
        return;
    c = json_object_new_object();
    json_object_object_add(c, "action", json_object_new_string(action ? action : ""));
    json_object_object_add(c, "target", json_object_new_string(target ? target : ""));
    json_object_object_add(c, "before", json_object_new_string(before ? before : "as-is"));
    json_object_object_add(c, "after", json_object_new_string(after ? after : ""));
    json_object_object_add(c, "reason", json_object_new_string(reason ? reason : ""));
    json_object_object_add(c, "runtime", json_object_new_boolean(runtime));
    json_object_object_add(c, "persistent", json_object_new_boolean(persistent));
    json_object_array_add(changes, c);
}

static void webd_port_dry_run_add_line(struct json_object *arr, const char *line)
{
    if (!arr || !json_object_is_type(arr, json_type_array) || !line || !line[0])
        return;
    json_object_array_add(arr, json_object_new_string(line));
}

static void webd_port_tx_add_file(struct json_object *files,
                                  const char *path,
                                  const char *role,
                                  int readable,
                                  int writable,
                                  int snapshot)
{
    struct json_object *o;

    if (!files || !json_object_is_type(files, json_type_array) || !path || !path[0])
        return;
    o = json_object_new_object();
    json_object_object_add(o, "path", json_object_new_string(path));
    json_object_object_add(o, "role", json_object_new_string(role ? role : ""));
    json_object_object_add(o, "readable", json_object_new_boolean(readable));
    json_object_object_add(o, "writable", json_object_new_boolean(writable));
    json_object_object_add(o, "snapshot", json_object_new_boolean(snapshot));
    json_object_array_add(files, o);
}

static int webd_port_ifname_strict_ok(const char *s)
{
    size_t i, len;

    if (!s || !s[0])
        return 0;
    len = strlen(s);
    if (len > IFNAMSIZ - 1 || s[0] == '-' || s[0] == '.' || strstr(s, ".."))
        return 0;
    for (i = 0; i < len; i++) {
        unsigned char c = (unsigned char)s[i];
        if (!(isalnum(c) || c == '_' || c == '-' || c == '.'))
            return 0;
    }
    return 1;
}

static int webd_port_uci_section_strict_ok(const char *s)
{
    size_t i, len;

    if (!s || !s[0])
        return 0;
    len = strlen(s);
    if (len > 64 || s[0] == '-' || s[0] == '.')
        return 0;
    for (i = 0; i < len; i++) {
        unsigned char c = (unsigned char)s[i];
        if (!(isalnum(c) || c == '_' || c == '-'))
            return 0;
    }
    return 1;
}

static int webd_port_vlan_id_ok(int vlan, int allow_zero)
{
    return allow_zero ? (vlan >= 0 && vlan <= 4094) : (vlan >= 1 && vlan <= 4094);
}

static int webd_port_tagged_vlans_strict_ok(struct json_object *arr, char *err, size_t err_len)
{
    int i, n, j;

    if (err && err_len)
        err[0] = '\0';
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
        int vlan;

        if (!vobj || json_object_is_type(vobj, json_type_object) ||
            json_object_is_type(vobj, json_type_array)) {
            if (err && err_len) snprintf(err, err_len, "invalid_tagged_vlan_type");
            return 0;
        }
        vlan = json_object_get_int(vobj);
        if (!webd_port_vlan_id_ok(vlan, 0)) {
            if (err && err_len) snprintf(err, err_len, "invalid_tagged_vlan_%d", vlan);
            return 0;
        }
        for (j = i + 1; j < n; j++) {
            if (json_object_get_int(json_object_array_get_idx(arr, j)) == vlan) {
                if (err && err_len) snprintf(err, err_len, "duplicate_tagged_vlan_%d", vlan);
                return 0;
            }
        }
    }
    return 1;
}

static struct json_object *webd_port_transaction_affected_files(void)
{
    struct json_object *files = json_object_new_array();

    webd_port_tx_add_file(files, WEBD_NETWORK_CONFIG_PATH, "primary_network_config",
                          access(WEBD_NETWORK_CONFIG_PATH, R_OK) == 0,
                          access(WEBD_NETWORK_CONFIG_PATH, W_OK) == 0,
                          1);
    webd_port_tx_add_file(files, WEBD_NETWORK_BACKUP_DIR, "snapshot_directory",
                          access(WEBD_NETWORK_BACKUP_DIR, R_OK) == 0,
                          webd_file_writable_parent(WEBD_NETWORK_BACKUP_DIR "/network"),
                          0);
    webd_port_tx_add_file(files, "/etc/dreamingwrt/config.db", "port_profile_config_db",
                          access("/etc/dreamingwrt/config.db", R_OK) == 0,
                          access("/etc/dreamingwrt/config.db", W_OK) == 0,
                          0);
    return files;
}

static struct json_object *webd_port_transaction_safety_checks(const char *ifname,
                                                               const char *owner_type,
                                                               int requires_confirm)
{
    struct json_object *checks = json_object_new_array();
    struct json_object *o;

#define ADD_CHECK(_name, _status, _required, _reason) do { \
        o = json_object_new_object(); \
        json_object_object_add(o, "name", json_object_new_string((_name))); \
        json_object_object_add(o, "status", json_object_new_string((_status))); \
        json_object_object_add(o, "required", json_object_new_boolean((_required))); \
        json_object_object_add(o, "reason", json_object_new_string((_reason))); \
        json_object_array_add(checks, o); \
    } while (0)

    ADD_CHECK("safe_ifname", (ifname && webd_safe_token(ifname)) ? "pass" : "fail", 1,
              "ifname must be a safe local interface token");
    ADD_CHECK("network_config_snapshot",
              access(WEBD_NETWORK_CONFIG_PATH, R_OK) == 0 ? "available" : "missing", 1,
              "/etc/config/network snapshot is required before any network mutation");
    ADD_CHECK("management_reachability",
              requires_confirm ? "required" : "optional", requires_confirm,
              "WAN/LAN/speed/duplex changes may briefly drop the management path");
    ADD_CHECK("live_vlan_mutation_executor",
              access("/etc/init.d/network", X_OK) == 0 ? "available" : "blocked", 1,
              "DSA bridge VLAN/profile apply can mutate UCI and reload network when capability checks pass");
    ADD_CHECK("confirm_live_apply", "enabled_for_vlan_runtime_only", 1,
              "transaction confirm records approval; rollback restores /etc/config/network snapshot and reloads network");
    if (owner_type && owner_type[0] && (!strcmp(owner_type, "wan") || !strcmp(owner_type, "lan")))
        ADD_CHECK("owner_scope", "pass", 1, "port belongs to a known WAN/LAN owner");
    else
        ADD_CHECK("owner_scope", "warn", 1, "unknown owner; mutation should stay preview-only");

#undef ADD_CHECK
    return checks;
}

struct json_object *webd_port_transaction_preview_from_plan(struct json_object *plan,
                                                                   struct json_object *body,
                                                                   const char *device_id)
{
    struct json_object *txp = json_object_new_object();
    struct json_object *dry = NULL;
    struct json_object *dry_diff = NULL;
    struct json_object *dry_uci = NULL;
    struct json_object *diff = json_object_new_array();
    struct json_object *uci = json_object_new_array();
    struct json_object *blocked_by = json_object_new_array();
    struct json_object *affected_files;
    struct json_object *safety;
    const char *ifname = app_nc_json_str(plan, "ifname", "");
    const char *owner_type = app_nc_json_str(plan, "current_owner_type", "");
    const char *owner_id = app_nc_json_str(plan, "current_owner_id", "");
    const char *target_owner_id = app_nc_json_str(plan, "target_owner_id", owner_id);
    int requires_confirm = app_nc_json_bool(plan, "requires_confirm", 0);
    int owner_migration = app_nc_json_bool(plan, "owner_migration_requested", 0);
    int vlan_present = app_nc_json_bool(plan, "vlan_profile_present", 0);
    int speed_present = app_nc_json_bool(plan, "speed_present", 0);
    int duplex_present = app_nc_json_bool(plan, "duplex_present", 0);
    int autoneg_present = app_nc_json_bool(plan, "autoneg_present", 0);
    int enabled_present = app_nc_json_bool(plan, "enabled_present", 0);
    int target_enabled = app_nc_json_bool(plan, "target_enabled", 1);

    if (owner_migration) {
        struct json_object *mp = webd_obj_child_obj(plan, "migration_plan");
        dry = mp ? webd_obj_child_obj(mp, "transaction_dry_run") : NULL;
    }
    if (!dry && vlan_present) {
        struct json_object *vp = webd_obj_child_obj(plan, "vlan_runtime_plan");
        dry = vp ? webd_obj_child_obj(vp, "transaction_dry_run") : NULL;
    }
    if (dry) {
        dry_diff = webd_obj_child_array(dry, "pseudo_unified_diff");
        dry_uci = webd_obj_child_array(dry, "uci_batch_preview");
    }
    if (dry_diff)
        diff = json_object_get(dry_diff);
    else {
        webd_port_dry_run_add_line(diff, "--- /etc/config/network");
        webd_port_dry_run_add_line(diff, "+++ /etc/config/network (dry-run, not applied)");
    }
    if (dry_uci)
        uci = json_object_get(dry_uci);

    if (enabled_present) {
        char line[192];
        snprintf(line, sizeof(line), "# %s %s enabled=%s via %s_enable (not applied in transaction preview)",
                 owner_type, owner_id, target_enabled ? "true" : "false",
                 !strcmp(owner_type, "wan") ? "wan" : "lan");
        webd_port_dry_run_add_line(uci, line);
        snprintf(line, sizeof(line), "@@ interface %s enabled", owner_id);
        webd_port_dry_run_add_line(diff, line);
        snprintf(line, sizeof(line), "+ option enabled '%d' # preview only", target_enabled ? 1 : 0);
        webd_port_dry_run_add_line(diff, line);
    }
    if (speed_present || duplex_present || autoneg_present) {
        char line[192];
        snprintf(line, sizeof(line), "# physical_port_config_apply %s speed/duplex/autoneg (not applied in transaction preview)",
                 ifname);
        webd_port_dry_run_add_line(uci, line);
        snprintf(line, sizeof(line), "@@ physical_port_config %s", ifname);
        webd_port_dry_run_add_line(diff, line);
        if (speed_present) {
            snprintf(line, sizeof(line), "+ speed_mbps: %d", webd_port_request_speed(body));
            webd_port_dry_run_add_line(diff, line);
        }
        if (duplex_present) {
            char duplex[16] = "";
            webd_normalize_duplex_value(app_nc_json_str(body, "duplex",
                                        app_nc_json_str(body, "configured_duplex", "")),
                                        duplex, sizeof(duplex));
            snprintf(line, sizeof(line), "+ duplex: %s", duplex[0] ? duplex : "invalid");
            webd_port_dry_run_add_line(diff, line);
        }
        if (autoneg_present) {
            int present = 0;
            int an = webd_port_request_autoneg(body, &present);
            snprintf(line, sizeof(line), "+ autoneg: %d", an);
            webd_port_dry_run_add_line(diff, line);
        }
    }

    if (owner_migration || !vlan_present)
        webd_array_add_unique_str(blocked_by, "network_mutation_executor_missing");

    affected_files = webd_port_transaction_affected_files();
    safety = webd_port_transaction_safety_checks(ifname, owner_type, requires_confirm);
    json_object_object_add(txp, "supported", json_object_new_boolean(1));
    json_object_object_add(txp, "read_only", json_object_new_boolean(owner_migration || !vlan_present));
    json_object_object_add(txp, "applies_changes", json_object_new_boolean(vlan_present && !owner_migration));
    json_object_object_add(txp, "transaction_only", json_object_new_boolean(owner_migration || !vlan_present));
    json_object_object_add(txp, "ifname", json_object_new_string(ifname));
    json_object_object_add(txp, "actor", json_object_new_string(device_id && device_id[0] ? device_id : "web"));
    json_object_object_add(txp, "scope", json_object_new_string("topology.port_manager"));
    json_object_object_add(txp, "requires_confirm", json_object_new_boolean(requires_confirm));
    json_object_object_add(txp, "requires_management_reachability", json_object_new_boolean(requires_confirm));
    json_object_object_add(txp, "management_reachability_scope", json_object_new_string("local_control_plane_limited"));
    json_object_object_add(txp, "affected_files", affected_files);
    json_object_object_add(txp, "safety_checks", safety);
    json_object_object_add(txp, "dry_run_diff", json_object_get(diff));
    json_object_object_add(txp, "pseudo_unified_diff", diff);
    json_object_object_add(txp, "uci_batch_preview", uci);
    json_object_object_add(txp, "blocked_by", blocked_by);
    json_object_object_add(txp, "from_owner_id", json_object_new_string(owner_id));
    json_object_object_add(txp, "to_owner_id", json_object_new_string(target_owner_id));
    json_object_object_add(txp, "confirm_behavior", json_object_new_string(vlan_present && !owner_migration ?
                           "live_vlan_apply_already_executed_pending_confirm_or_rollback" :
                           "record_only_no_live_network_mutation"));
    json_object_object_add(txp, "live_apply_requires", json_object_new_string(vlan_present && !owner_migration ?
                           "create transaction or apply with confirm=false; rollback if health/readback fails" :
                           "repeat /api/v1/topology/node/ports/apply with confirm=true"));
    json_object_object_add(txp, "reason", json_object_new_string(vlan_present && !owner_migration ?
                           "dsa_bridge_vlan_runtime_transaction_supported_when_capability_checks_pass" :
                           "transaction_preview_only_network_mutation_executor_missing"));
    return txp;
}

static struct json_object *webd_port_profile_lookup_for_plan(const char *profile_id)
{
    struct json_object *params = NULL;
    struct json_object *resp = NULL;
    struct json_object *data = NULL;
    struct json_object *profile = NULL;

    if (!profile_id || !profile_id[0] || !webd_safe_token(profile_id))
        return NULL;
    params = json_object_new_object();
    json_object_object_add(params, "id", json_object_new_string(profile_id));
    resp = app_ubus_invoke_timeout("physical_port_profile_get", params, 3000);
    json_object_put(params);
    data = webd_data_from_jmx_response(resp);
    if (data) {
        struct json_object *p = webd_obj_child_obj(data, "profile");
        if (p)
            profile = json_object_get(p);
        json_object_put(data);
    }
    if (resp)
        json_object_put(resp);
    return profile;
}

static struct json_object *webd_port_effective_vlan_target(struct json_object *body,
                                                           struct json_object *warnings)
{
    struct json_object *target = json_object_new_object();
    struct json_object *tagged = NULL;
    struct json_object *profile = NULL;
    struct json_object *profile_tagged = NULL;
    const char *profile_id = app_nc_json_str(body, "profile_id",
                                             app_nc_json_str(body, "profile", ""));
    int native_present = app_nc_json_has(body, "native_vlan") || app_nc_json_has(body, "vlan_id");
    int tagged_present = webd_port_request_tagged_vlans(body, &tagged) > 0;
    int profile_present = app_nc_json_has(body, "profile_id") || app_nc_json_has(body, "profile");
    int native_vlan = app_nc_json_int(body, "native_vlan",
                                      app_nc_json_int(body, "vlan_id", 0));
    int inherited_native = 0;
    int inherited_tagged = 0;

    if (profile_id && profile_id[0]) {
        profile = webd_port_profile_lookup_for_plan(profile_id);
        if (profile) {
            if (!native_present) {
                native_vlan = app_nc_json_int(profile, "native_vlan", native_vlan);
                inherited_native = 1;
            }
            if (!tagged_present) {
                profile_tagged = webd_obj_child_array(profile, "tagged_vlans");
                if (profile_tagged) {
                    tagged = profile_tagged;
                    tagged_present = 1;
                    inherited_tagged = 1;
                }
            }
        } else if (warnings) {
            json_object_array_add(warnings, json_object_new_string("profile_not_found_for_dry_run"));
        }
    }

    json_object_object_add(target, "profile_present", json_object_new_boolean(profile_present));
    json_object_object_add(target, "profile_id", json_object_new_string(profile_id ? profile_id : ""));
    json_object_object_add(target, "profile_found", json_object_new_boolean(profile != NULL));
    json_object_object_add(target, "native_vlan_present", json_object_new_boolean(native_present || inherited_native));
    json_object_object_add(target, "native_vlan", json_object_new_int(native_vlan));
    json_object_object_add(target, "native_vlan_inherited_from_profile", json_object_new_boolean(inherited_native));
    json_object_object_add(target, "tagged_vlans_present", json_object_new_boolean(tagged_present));
    json_object_object_add(target, "tagged_vlans_inherited_from_profile", json_object_new_boolean(inherited_tagged));
    if (tagged && json_object_is_type(tagged, json_type_array))
        json_object_object_add(target, "tagged_vlans", json_object_get(tagged));
    else
        json_object_object_add(target, "tagged_vlans", json_object_new_array());
    if (profile)
        json_object_object_add(target, "profile", profile);
    else
        json_object_object_add(target, "profile", json_object_new_null());
    return target;
}

static void webd_port_dry_run_add_vlan_changes(struct json_object *dry,
                                               const char *ifname,
                                               const char *bridge_name,
                                               struct json_object *body)
{
    struct json_object *changes = webd_obj_child_array(dry, "changes");
    struct json_object *uci = webd_obj_child_array(dry, "uci_batch_preview");
    struct json_object *diff = webd_obj_child_array(dry, "pseudo_unified_diff");
    struct json_object *warnings = webd_obj_child_array(dry, "warnings");
    struct json_object *target = webd_port_effective_vlan_target(body, warnings);
    struct json_object *tagged = webd_obj_child_array(target, "tagged_vlans");
    int native_vlan = app_nc_json_int(target, "native_vlan", 0);
    int tagged_count = tagged ? (int)json_object_array_length(tagged) : 0;
    int i;
    char buf[256];

    json_object_object_add(dry, "vlan_target", target);
    if (app_nc_json_bool(target, "profile_present", 0)) {
        snprintf(buf, sizeof(buf), "physical_port_config.%s.profile_id", ifname ? ifname : "");
        webd_port_dry_run_add_change(changes, "set_config_db", buf, "as-is",
                                     app_nc_json_str(target, "profile_id", ""),
                                     "save selected port profile in DreamingWrt config.db", 0, 1);
    }
    if (native_vlan > 0 || tagged_count > 0) {
        snprintf(buf, sizeof(buf), "network.device.%s.vlan_filtering", bridge_name ? bridge_name : "br-lan");
        webd_port_dry_run_add_change(changes, "ensure_bridge_vlan_filtering", buf, "as-is", "1",
                                     "bridge-vlan runtime apply requires vlan_filtering", 1, 1);
        snprintf(buf, sizeof(buf), "uci set network.@device[?name='%s'].vlan_filtering='1'",
                 bridge_name ? bridge_name : "br-lan");
        webd_port_dry_run_add_line(uci, buf);
        snprintf(buf, sizeof(buf), "@@ device %s", bridge_name ? bridge_name : "br-lan");
        webd_port_dry_run_add_line(diff, buf);
        webd_port_dry_run_add_line(diff, "+ option vlan_filtering '1'");
    }
    if (native_vlan > 0) {
        char after[128];
        snprintf(after, sizeof(after), "vlan=%d ports='%s:u*'", native_vlan, ifname ? ifname : "");
        snprintf(buf, sizeof(buf), "network.bridge-vlan.%s.%d", bridge_name ? bridge_name : "br-lan", native_vlan);
        webd_port_dry_run_add_change(changes, "ensure_untagged_native_vlan_membership",
                                     buf, "as-is", after,
                                     "native VLAN/profile dry-run; not applied by webd", 1, 1);
        snprintf(buf, sizeof(buf), "uci add_list network.@bridge-vlan[?device='%s'][?vlan='%d'].ports='%s:u*'",
                 bridge_name ? bridge_name : "br-lan", native_vlan, ifname ? ifname : "");
        webd_port_dry_run_add_line(uci, buf);
        snprintf(buf, sizeof(buf), "@@ bridge-vlan %s vlan %d", bridge_name ? bridge_name : "br-lan", native_vlan);
        webd_port_dry_run_add_line(diff, buf);
        snprintf(buf, sizeof(buf), "+ list ports '%s:u*'", ifname ? ifname : "");
        webd_port_dry_run_add_line(diff, buf);
    }
    for (i = 0; i < tagged_count; i++) {
        int vlan = json_object_get_int(json_object_array_get_idx(tagged, i));
        char after[128];

        if (vlan <= 0 || vlan > 4094)
            continue;
        snprintf(after, sizeof(after), "vlan=%d ports='%s:t'", vlan, ifname ? ifname : "");
        snprintf(buf, sizeof(buf), "network.bridge-vlan.%s.%d", bridge_name ? bridge_name : "br-lan", vlan);
        webd_port_dry_run_add_change(changes, "ensure_tagged_vlan_membership",
                                     buf, "as-is", after,
                                     "tagged VLAN/profile dry-run; not applied by webd", 1, 1);
        snprintf(buf, sizeof(buf), "uci add_list network.@bridge-vlan[?device='%s'][?vlan='%d'].ports='%s:t'",
                 bridge_name ? bridge_name : "br-lan", vlan, ifname ? ifname : "");
        webd_port_dry_run_add_line(uci, buf);
        snprintf(buf, sizeof(buf), "@@ bridge-vlan %s vlan %d", bridge_name ? bridge_name : "br-lan", vlan);
        webd_port_dry_run_add_line(diff, buf);
        snprintf(buf, sizeof(buf), "+ list ports '%s:t'", ifname ? ifname : "");
        webd_port_dry_run_add_line(diff, buf);
    }
}

static void webd_port_dry_run_add_migration_changes(struct json_object *dry,
                                                    const char *ifname,
                                                    const char *bridge_name,
                                                    const char *from_owner_id,
                                                    const char *to_owner_id)
{
    struct json_object *changes = webd_obj_child_array(dry, "changes");
    struct json_object *uci = webd_obj_child_array(dry, "uci_batch_preview");
    struct json_object *diff = webd_obj_child_array(dry, "pseudo_unified_diff");
    struct json_object *warnings = webd_obj_child_array(dry, "warnings");
    int from_lan = from_owner_id && !strcmp(from_owner_id, "lan");
    int to_lan = to_owner_id && !strcmp(to_owner_id, "lan");
    int from_wan = from_owner_id && !strncmp(from_owner_id, "wan", 3);
    int to_wan = to_owner_id && !strncmp(to_owner_id, "wan", 3);
    char buf[256];

    if (from_lan && !to_lan) {
        snprintf(buf, sizeof(buf), "network.device.%s.ports", bridge_name ? bridge_name : "br-lan");
        webd_port_dry_run_add_change(changes, "remove_bridge_port", buf, ifname ? ifname : "",
                                     "removed from LAN bridge",
                                     "moving management-side LAN port requires reachability rollback", 1, 1);
        snprintf(buf, sizeof(buf), "uci del_list network.@device[?name='%s'].ports='%s'",
                 bridge_name ? bridge_name : "br-lan", ifname ? ifname : "");
        webd_port_dry_run_add_line(uci, buf);
        webd_port_dry_run_add_line(diff, "@@ device br-lan ports");
        snprintf(buf, sizeof(buf), "- list ports '%s'", ifname ? ifname : "");
        webd_port_dry_run_add_line(diff, buf);
        if (warnings)
            json_object_array_add(warnings, json_object_new_string("dry_run_would_remove_requested_port_from_lan_bridge"));
    }
    if (!from_lan && to_lan) {
        snprintf(buf, sizeof(buf), "network.device.%s.ports", bridge_name ? bridge_name : "br-lan");
        webd_port_dry_run_add_change(changes, "add_bridge_port", buf, "as-is",
                                     ifname ? ifname : "",
                                     "moving port into LAN bridge", 1, 1);
        snprintf(buf, sizeof(buf), "uci add_list network.@device[?name='%s'].ports='%s'",
                 bridge_name ? bridge_name : "br-lan", ifname ? ifname : "");
        webd_port_dry_run_add_line(uci, buf);
        webd_port_dry_run_add_line(diff, "@@ device br-lan ports");
        snprintf(buf, sizeof(buf), "+ list ports '%s'", ifname ? ifname : "");
        webd_port_dry_run_add_line(diff, buf);
    }
    if (to_wan) {
        snprintf(buf, sizeof(buf), "network.interface.%s.device", to_owner_id ? to_owner_id : "");
        webd_port_dry_run_add_change(changes, "set_interface_device", buf, "as-is",
                                     ifname ? ifname : "",
                                     "assign physical port to target WAN interface", 1, 1);
        snprintf(buf, sizeof(buf), "uci set network.%s.device='%s'",
                 to_owner_id ? to_owner_id : "", ifname ? ifname : "");
        webd_port_dry_run_add_line(uci, buf);
        snprintf(buf, sizeof(buf), "@@ interface %s", to_owner_id ? to_owner_id : "");
        webd_port_dry_run_add_line(diff, buf);
        snprintf(buf, sizeof(buf), "+ option device '%s'", ifname ? ifname : "");
        webd_port_dry_run_add_line(diff, buf);
    }
    if (from_wan && to_wan && from_owner_id && to_owner_id && strcmp(from_owner_id, to_owner_id)) {
        snprintf(buf, sizeof(buf), "network.interface.%s.device", from_owner_id);
        webd_port_dry_run_add_change(changes, "clear_or_replace_old_interface_device", buf,
                                     ifname ? ifname : "", "requires replacement device or disable",
                                     "avoid two WAN interfaces claiming the same physical port", 1, 1);
        if (warnings)
            json_object_array_add(warnings, json_object_new_string("source_wan_device_replacement_not_selected"));
    }
    if (from_wan && to_lan) {
        snprintf(buf, sizeof(buf), "network.interface.%s.device", from_owner_id ? from_owner_id : "");
        webd_port_dry_run_add_change(changes, "clear_or_replace_old_wan_device", buf,
                                     ifname ? ifname : "", "requires replacement device or disable",
                                     "moving WAN port into LAN would disconnect the source WAN", 1, 1);
        if (warnings)
            json_object_array_add(warnings, json_object_new_string("moving_wan_port_to_lan_requires_wan_replacement_or_disable"));
    }
}

static struct json_object *webd_port_network_transaction_dry_run(const char *ifname,
                                                                 const char *operation,
                                                                 struct json_object *body,
                                                                 struct json_object *port,
                                                                 const char *from_owner_id,
                                                                 const char *to_owner_id)
{
    struct json_object *dry = json_object_new_object();
    struct json_object *changes = json_object_new_array();
    struct json_object *uci = json_object_new_array();
    struct json_object *diff = json_object_new_array();
    struct json_object *warnings = json_object_new_array();
    struct json_object *blocked_by = json_object_new_array();
    struct json_object *rollback = json_object_new_object();
    const char *bridge_name = app_nc_json_str(body, "bridge",
                                              app_nc_json_str(body, "bridge_name", "br-lan"));
    int vlan_requested = app_nc_json_has(body, "native_vlan") || app_nc_json_has(body, "vlan_id") ||
                         app_nc_json_has(body, "profile_id") || app_nc_json_has(body, "profile") ||
                         app_nc_json_has(body, "tagged_vlans");
    char buf[256];

    if (!bridge_name || !bridge_name[0])
        bridge_name = "br-lan";
    json_object_object_add(dry, "supported", json_object_new_boolean(1));
    json_object_object_add(dry, "read_only", json_object_new_boolean(1));
    json_object_object_add(dry, "applies_changes", json_object_new_boolean(0));
    json_object_object_add(dry, "apply_supported", json_object_new_boolean(!strcmp(operation ? operation : "", "vlan_runtime_apply")));
    json_object_object_add(dry, "sanitized", json_object_new_boolean(1));
    json_object_object_add(dry, "secret_fields_exposed", json_object_new_boolean(0));
    json_object_object_add(dry, "format", json_object_new_string("uci_intent_diff_not_applied"));
    json_object_object_add(dry, "operation", json_object_new_string(operation ? operation : ""));
    json_object_object_add(dry, "ifname", json_object_new_string(ifname ? ifname : ""));
    json_object_object_add(dry, "bridge", json_object_new_string(bridge_name));
    json_object_object_add(dry, "from_owner_id", json_object_new_string(from_owner_id ? from_owner_id : ""));
    json_object_object_add(dry, "to_owner_id", json_object_new_string(to_owner_id ? to_owner_id : ""));
    json_object_object_add(dry, "bridge_cmd_available", json_object_new_boolean(webd_bridge_cmd_path()[0] != 0));
    json_object_object_add(dry, "network_config_readable", json_object_new_boolean(access("/etc/config/network", R_OK) == 0));
    json_object_object_add(dry, "changes", changes);
    json_object_object_add(dry, "uci_batch_preview", uci);
    json_object_object_add(dry, "pseudo_unified_diff", diff);
    json_object_object_add(dry, "warnings", warnings);
    json_object_object_add(dry, "blocked_by", blocked_by);
    if (port)
        json_object_object_add(dry, "current_port", json_object_get(port));

    webd_port_dry_run_add_line(diff, "--- /etc/config/network");
    webd_port_dry_run_add_line(diff, "+++ /etc/config/network (dry-run, not applied)");

    if (vlan_requested)
        webd_port_dry_run_add_vlan_changes(dry, ifname, bridge_name, body);
    if ((from_owner_id && to_owner_id && strcmp(from_owner_id, to_owner_id)) ||
        (operation && strstr(operation, "reassignment")))
        webd_port_dry_run_add_migration_changes(dry, ifname, bridge_name, from_owner_id, to_owner_id);

    snprintf(buf, sizeof(buf), "cp /etc/config/network /etc/dreamingwrt/network-backup/network.$TS");
    json_object_object_add(rollback, "snapshot_command_preview", json_object_new_string(buf));
    json_object_object_add(rollback, "restore_command_preview",
                           json_object_new_string("cp <snapshot> /etc/config/network && /etc/init.d/network reload"));
    json_object_object_add(rollback, "reachability_probe", json_object_new_string("local_control_plane_limited"));
    json_object_object_add(rollback, "manual_rollback_supported", json_object_new_boolean(1));
    json_object_object_add(rollback, "automatic_rollback", json_object_new_boolean(1));
    json_object_object_add(rollback, "auto_rollback_worker", json_object_new_boolean(1));
    json_object_object_add(rollback, "auto_rollback_worker_owner", json_object_new_string("dreamingwrt-init"));
    json_object_object_add(rollback, "auto_rollback_scope", json_object_new_string("/etc/config/network snapshot restore only"));
    json_object_object_add(rollback, "executor", json_object_new_string("/etc/config/network snapshot restore"));
    json_object_object_add(rollback, "reason", json_object_new_string(!strcmp(operation ? operation : "", "vlan_runtime_apply") ?
                           "guarded_vlan_runtime_executor_available" :
                           "network_mutation_executor_still_missing; persistent_auto_rollback_worker_ready"));
    json_object_object_add(dry, "rollback_plan", rollback);
    if (strcmp(operation ? operation : "", "vlan_runtime_apply"))
        json_object_array_add(blocked_by, json_object_new_string("network_mutation_executor_missing"));
    json_object_object_add(dry, "change_count", json_object_new_int((int)json_object_array_length(changes)));
    json_object_object_add(dry, "diff_generated", json_object_new_boolean(json_object_array_length(changes) > 0));
    json_object_object_add(dry, "reason", json_object_new_string(!strcmp(operation ? operation : "", "vlan_runtime_apply") ?
                           "dry_run_only_guarded_vlan_transaction_available" :
                           "dry_run_only_transaction_executor_pending"));
    return dry;
}

static void webd_port_vlan_add_sysfs_probe(struct json_object *vp,
                                           const char *ifname,
                                           const char *bridge_name)
{
    struct json_object *probe = json_object_new_object();
    char path[256];
    char line[128] = "";
    int bridge_exists = 0;
    int vlan_filtering = -1;
    int if_exists = 0;
    int if_is_bridge_member = 0;
    int if_has_upper_bridge = 0;
    int if_has_lower_ports = 0;
    int if_is_dsa_port = 0;
    int bridge_has_lower_if = 0;

    if (!ifname)
        ifname = "";
    if (!bridge_name || !bridge_name[0])
        bridge_name = "br-lan";

    snprintf(path, sizeof(path), "/sys/class/net/%s", ifname);
    if_exists = ifname[0] && access(path, F_OK) == 0;

    snprintf(path, sizeof(path), "/sys/class/net/%s/bridge", bridge_name);
    bridge_exists = access(path, F_OK) == 0;
    snprintf(path, sizeof(path), "/sys/class/net/%s/bridge/vlan_filtering", bridge_name);
    if (webd_file_read_first_line(path, line, sizeof(line)) == 0 && line[0])
        vlan_filtering = atoi(line);

    snprintf(path, sizeof(path), "/sys/class/net/%s/brport", ifname);
    if_is_bridge_member = if_exists && access(path, F_OK) == 0;
    snprintf(path, sizeof(path), "/sys/class/net/%s/upper_%s", ifname, bridge_name);
    if_has_upper_bridge = if_exists && access(path, F_OK) == 0;
    snprintf(path, sizeof(path), "/sys/class/net/%s/lower_%s", bridge_name, ifname);
    bridge_has_lower_if = bridge_exists && access(path, F_OK) == 0;
    snprintf(path, sizeof(path), "/sys/class/net/%s/lower_*", ifname);
    (void)path;
    {
        char lower_dir[256];
        snprintf(lower_dir, sizeof(lower_dir), "/sys/class/net/%s", ifname);
        if_has_lower_ports = 0;
        if (if_exists) {
            DIR *dir = opendir(lower_dir);
            struct dirent *de;
            if (dir) {
                while ((de = readdir(dir)) != NULL) {
                    if (!strncmp(de->d_name, "lower_", 6)) {
                        if_has_lower_ports = 1;
                        break;
                    }
                }
                closedir(dir);
            }
        }
    }
    snprintf(path, sizeof(path), "/sys/class/net/%s/dsa", ifname);
    if_is_dsa_port = access(path, F_OK) == 0;
    if (!if_is_dsa_port) {
        snprintf(path, sizeof(path), "/sys/class/net/%s/phys_port_name", ifname);
        if (webd_file_read_first_line(path, line, sizeof(line)) == 0 && line[0] &&
            (strstr(line, "lan") || strstr(line, "wan") || strstr(line, "p")))
            if_is_dsa_port = 1;
    }

    json_object_object_add(probe, "ifname", json_object_new_string(ifname));
    json_object_object_add(probe, "bridge", json_object_new_string(bridge_name));
    json_object_object_add(probe, "if_exists", json_object_new_boolean(if_exists));
    json_object_object_add(probe, "bridge_exists", json_object_new_boolean(bridge_exists));
    json_object_object_add(probe, "bridge_vlan_filtering", vlan_filtering < 0 ?
                           json_object_new_null() : json_object_new_boolean(vlan_filtering > 0));
    json_object_object_add(probe, "bridge_vlan_filtering_raw", vlan_filtering < 0 ?
                           json_object_new_string("") : json_object_new_int(vlan_filtering));
    json_object_object_add(probe, "if_is_bridge_member", json_object_new_boolean(if_is_bridge_member));
    json_object_object_add(probe, "if_has_upper_bridge", json_object_new_boolean(if_has_upper_bridge));
    json_object_object_add(probe, "bridge_has_lower_if", json_object_new_boolean(bridge_has_lower_if));
    json_object_object_add(probe, "if_has_lower_ports", json_object_new_boolean(if_has_lower_ports));
    json_object_object_add(probe, "if_is_dsa_port", json_object_new_boolean(if_is_dsa_port));
    json_object_object_add(probe, "dsa_model_likely", json_object_new_boolean(if_is_dsa_port || if_has_lower_ports));
    json_object_object_add(probe, "plain_linux_bridge_likely",
                           json_object_new_boolean(bridge_exists && if_is_bridge_member && !if_is_dsa_port));
    json_object_object_add(vp, "runtime_probe", probe);
}

static void webd_port_vlan_add_network_config_probe(struct json_object *vp,
                                                    const char *ifname,
                                                    const char *bridge_name)
{
    struct json_object *cfg = json_object_new_object();
    FILE *fp;
    char line[512];
    char current[64] = "";
    int bridge_device_found = 0;
    int bridge_has_port = 0;
    int bridge_vlan_sections = 0;
    int if_device_refs = 0;
    int vlan_filtering_option = -1;

    if (!ifname)
        ifname = "";
    if (!bridge_name || !bridge_name[0])
        bridge_name = "br-lan";

    fp = fopen("/etc/config/network", "r");
    if (fp) {
        while (fgets(line, sizeof(line), fp)) {
            char *p = line;
            while (*p && isspace((unsigned char)*p))
                p++;
            if (!strncmp(p, "config ", 7)) {
                current[0] = '\0';
                if (strstr(p, "device"))
                    snprintf(current, sizeof(current), "device");
                else if (strstr(p, "bridge-vlan"))
                    snprintf(current, sizeof(current), "bridge-vlan");
                else if (strstr(p, "interface"))
                    snprintf(current, sizeof(current), "interface");
                if (!strcmp(current, "bridge-vlan"))
                    bridge_vlan_sections++;
                continue;
            }
            if (!strcmp(current, "device")) {
                if (strstr(p, "option name") && strstr(p, bridge_name))
                    bridge_device_found = 1;
                if (ifname[0] && strstr(p, "list ports") && strstr(p, ifname))
                    bridge_has_port = 1;
                if (strstr(p, "option vlan_filtering")) {
                    if (strstr(p, "'1'") || strstr(p, " 1") || strstr(p, "\"1\""))
                        vlan_filtering_option = 1;
                    else if (strstr(p, "'0'") || strstr(p, " 0") || strstr(p, "\"0\""))
                        vlan_filtering_option = 0;
                }
            }
            if (ifname[0] && (strstr(p, "option device") || strstr(p, "option ifname") ||
                              strstr(p, "list ports")) && strstr(p, ifname))
                if_device_refs++;
        }
        fclose(fp);
    }
    json_object_object_add(cfg, "readable", json_object_new_boolean(fp != NULL));
    json_object_object_add(cfg, "bridge_device_found", json_object_new_boolean(bridge_device_found));
    json_object_object_add(cfg, "bridge_has_requested_port", json_object_new_boolean(bridge_has_port));
    json_object_object_add(cfg, "bridge_vlan_sections", json_object_new_int(bridge_vlan_sections));
    json_object_object_add(cfg, "requested_ifname_references", json_object_new_int(if_device_refs));
    json_object_object_add(cfg, "vlan_filtering_option", vlan_filtering_option < 0 ?
                           json_object_new_null() : json_object_new_boolean(vlan_filtering_option > 0));
    json_object_object_add(vp, "network_config_probe", cfg);
}

static struct json_object *webd_port_migration_plan(const char *ifname,
                                                    struct json_object *port,
                                                    struct json_object *body,
                                                    const char *from_owner_type,
                                                    const char *from_owner_id,
                                                    const char *to_owner_type,
                                                    const char *to_owner_id)
{
    struct json_object *mp = json_object_new_object();
    struct json_object *affected_networks = json_object_new_array();
    struct json_object *affected_ports = json_object_new_array();
    struct json_object *validation = json_object_new_object();
    struct json_object *planned_steps = json_object_new_array();
    struct json_object *blocked_by = json_object_new_array();

    webd_port_plan_add_unique_str(affected_networks, from_owner_id);
    webd_port_plan_add_unique_str(affected_networks, to_owner_id);
    webd_port_plan_add_unique_str(affected_ports, ifname);

    json_object_object_add(mp, "requested", json_object_new_boolean(1));
    json_object_object_add(mp, "supported", json_object_new_boolean(0));
    json_object_object_add(mp, "preview_supported", json_object_new_boolean(1));
    json_object_object_add(mp, "apply_supported", json_object_new_boolean(0));
    json_object_object_add(mp, "transaction_required", json_object_new_boolean(1));
    json_object_object_add(mp, "rollback_supported", json_object_new_boolean(1));
    json_object_object_add(mp, "rollback_scope", json_object_new_string("/etc/config/network snapshot restore"));
    json_object_object_add(mp, "requires_confirm", json_object_new_boolean(1));
    json_object_object_add(mp, "ifname", json_object_new_string(ifname ? ifname : ""));
    json_object_object_add(mp, "from_owner_type", json_object_new_string(from_owner_type ? from_owner_type : ""));
    json_object_object_add(mp, "from_owner_id", json_object_new_string(from_owner_id ? from_owner_id : ""));
    json_object_object_add(mp, "to_owner_type", json_object_new_string(to_owner_type ? to_owner_type : ""));
    json_object_object_add(mp, "to_owner_id", json_object_new_string(to_owner_id ? to_owner_id : ""));
    json_object_object_add(mp, "affected_networks", affected_networks);
    json_object_object_add(mp, "affected_ports", affected_ports);
    json_object_object_add(mp, "reason", json_object_new_string("network_owner_migration_transaction_pending"));
    json_object_object_add(mp, "message", json_object_new_string("port migration needs an atomic netifd/uci/network transaction with management reachability check and rollback; current backend only returns a safe preview plan"));
    json_object_object_add(mp, "next_backend_step", json_object_new_string("implement transactional_multi_owner_apply_with_uci_backup_validate_and_rollback"));
    json_object_array_add(planned_steps, json_object_new_string("snapshot /etc/config/network and current ubus network status"));
    json_object_array_add(planned_steps, json_object_new_string("generate owner/bridge/member diff without exposing PPPoE secrets"));
    json_object_array_add(planned_steps, json_object_new_string("apply through netifd transaction window"));
    json_object_array_add(planned_steps, json_object_new_string("probe management address and target WAN/LAN health"));
    json_object_array_add(planned_steps, json_object_new_string("rollback on failed reachability or netifd error"));
    json_object_array_add(blocked_by, json_object_new_string("uci_network_transaction_engine_missing"));
    /* snapshot rollback and limited local reachability probe are available; mutation executor is still disabled */
    json_object_object_add(mp, "planned_steps", planned_steps);
    json_object_object_add(mp, "blocked_by", blocked_by);

    json_object_object_add(validation, "safe_token_ifname", json_object_new_boolean(ifname && webd_safe_token(ifname)));
    json_object_object_add(validation, "current_owner_known", json_object_new_boolean((from_owner_type && from_owner_type[0]) || (from_owner_id && from_owner_id[0])));
    json_object_object_add(validation, "target_owner_requested", json_object_new_boolean((to_owner_type && to_owner_type[0]) || (to_owner_id && to_owner_id[0])));
    json_object_object_add(validation, "management_lockout_check", json_object_new_string("pending"));
    json_object_object_add(validation, "netifd_reload_check", json_object_new_string("pending"));
    json_object_object_add(validation, "rollback_probe", json_object_new_string("pending"));
    json_object_object_add(mp, "validation", validation);
    json_object_object_add(mp, "transaction_preflight",
                           webd_port_network_transaction_preflight(ifname, "br-lan",
                                                                   from_owner_id, to_owner_id));
    json_object_object_add(mp, "transaction_dry_run",
                           webd_port_network_transaction_dry_run(ifname, "port_reassignment",
                                                                 body, port, from_owner_id, to_owner_id));

    if (port)
        json_object_object_add(mp, "current_port", json_object_get(port));
    return mp;
}

static struct json_object *webd_port_vlan_runtime_plan(const char *ifname,
                                                       struct json_object *body,
                                                       struct json_object *port)
{
    struct json_object *vp = json_object_new_object();
    struct json_object *tagged = NULL;
    struct json_object *planned_steps = json_object_new_array();
    struct json_object *safety_checks = json_object_new_array();
    struct json_object *blocked_by = json_object_new_array();
    const char *profile_id = app_nc_json_str(body, "profile_id",
                                             app_nc_json_str(body, "profile", ""));
    int native_vlan = app_nc_json_int(body, "native_vlan",
                                      app_nc_json_int(body, "vlan_id", 0));
    const char *bridge_name = app_nc_json_str(body, "bridge",
                                              app_nc_json_str(body, "bridge_name", "br-lan"));
    int has_br_lan = access("/sys/class/net/br-lan/bridge", F_OK) == 0;
    const char *bridge_cmd = webd_bridge_cmd_path();
    int has_bridge_cmd = bridge_cmd[0] != 0;
    int has_network_config = access("/etc/config/network", R_OK) == 0;
    const char *owner_id = port ? app_nc_json_str(port, "owner_id", "") : "";

    json_object_object_add(vp, "requested", json_object_new_boolean(1));
    json_object_object_add(vp, "save_supported", json_object_new_boolean(1));
    json_object_object_add(vp, "runtime_apply_supported", json_object_new_boolean(1));
    json_object_object_add(vp, "transaction_required", json_object_new_boolean(1));
    json_object_object_add(vp, "rollback_supported", json_object_new_boolean(1));
    json_object_object_add(vp, "rollback_scope", json_object_new_string("/etc/config/network snapshot restore"));
    json_object_object_add(vp, "ifname", json_object_new_string(ifname ? ifname : ""));
    json_object_object_add(vp, "native_vlan_present", json_object_new_boolean(app_nc_json_has(body, "native_vlan") || app_nc_json_has(body, "vlan_id")));
    json_object_object_add(vp, "native_vlan", json_object_new_int(native_vlan));
    json_object_object_add(vp, "profile_present", json_object_new_boolean(app_nc_json_has(body, "profile_id") || app_nc_json_has(body, "profile")));
    json_object_object_add(vp, "profile_id", json_object_new_string(profile_id ? profile_id : ""));
    json_object_object_add(vp, "bridge", json_object_new_string(bridge_name && bridge_name[0] ? bridge_name : "br-lan"));
    if (webd_port_request_tagged_vlans(body, &tagged) > 0 && tagged)
        json_object_object_add(vp, "tagged_vlans", json_object_get(tagged));
    else
        json_object_object_add(vp, "tagged_vlans", json_object_new_array());
    json_object_object_add(vp, "tagged_vlans_present", json_object_new_boolean(tagged != NULL));
    json_object_object_add(vp, "network_config_readable", json_object_new_boolean(has_network_config));
    json_object_object_add(vp, "bridge_runtime_visible", json_object_new_boolean(has_br_lan));
    json_object_object_add(vp, "bridge_cmd_available", json_object_new_boolean(has_bridge_cmd));
    json_object_object_add(vp, "bridge_cmd", json_object_new_string(bridge_cmd));
    json_object_object_add(vp, "network_model_hint",
                           json_object_new_string(has_br_lan ? "linux_bridge_or_dsa_bridge" : "unknown_or_non_bridge"));
    json_object_object_add(vp, "apply_supported", json_object_new_boolean(1));
    json_object_object_add(vp, "reason", json_object_new_string("dsa_bridge_vlan_uci_reload_guarded"));
    json_object_object_add(vp, "message", json_object_new_string("VLAN/profile can be applied through a guarded DSA bridge-vlan UCI transaction with reload, readback, management health probe and rollback"));
    json_object_object_add(vp, "next_backend_step", json_object_new_string("true_hardware_acceptance_on_30_1_and_31_6"));
    json_object_array_add(planned_steps, json_object_new_string("read /etc/config/network and detect DSA/swconfig/plain bridge model"));
    json_object_array_add(planned_steps, json_object_new_string("build bridge-vlan/member diff for the requested port/profile"));
    json_object_array_add(planned_steps, json_object_new_string("backup network config and runtime status"));
    json_object_array_add(planned_steps, json_object_new_string("apply through UCI/netifd, then verify bridge vlan show and ubus interface status"));
    json_object_array_add(planned_steps, json_object_new_string("probe management IP and rollback automatically on failure"));
    json_object_array_add(safety_checks, json_object_new_string("management_lockout_check"));
    json_object_array_add(safety_checks, json_object_new_string("wan_health_regression_check"));
    json_object_array_add(safety_checks, json_object_new_string("bridge_vlan_runtime_verification"));
    json_object_array_add(safety_checks, json_object_new_string("rollback_probe"));
    if (!has_network_config)
        json_object_array_add(blocked_by, json_object_new_string("network_config_unreadable"));
    if (!has_bridge_cmd)
        json_object_array_add(blocked_by, json_object_new_string("bridge_command_unavailable"));
    if (!has_br_lan)
        json_object_array_add(blocked_by, json_object_new_string("bridge_runtime_missing"));
    webd_port_vlan_add_sysfs_probe(vp, ifname, bridge_name);
    webd_port_vlan_add_network_config_probe(vp, ifname, bridge_name);
    json_object_object_add(vp, "transaction_preflight",
                           webd_port_network_transaction_preflight(ifname, bridge_name,
                                                                   owner_id, owner_id));
    json_object_object_add(vp, "transaction_dry_run",
                           webd_port_network_transaction_dry_run(ifname, "vlan_runtime_apply",
                                                                 body, port, owner_id, owner_id));
    json_object_object_add(vp, "planned_steps", planned_steps);
    json_object_object_add(vp, "safety_checks", safety_checks);
    json_object_object_add(vp, "blocked_by", blocked_by);
    if (port)
        json_object_object_add(vp, "current_port", json_object_get(port));
    return vp;
}

int webd_port_profiles_path(const char *path, char *id, size_t id_len)
{
    static const char *bases[] = {
        "/api/v1/topology/port-profiles",
        "/api/v1/network/port-profiles",
        NULL
    };
    int i;

    if (id && id_len)
        id[0] = '\0';
    if (!path)
        return 0;
    for (i = 0; bases[i]; i++) {
        size_t blen = strlen(bases[i]);
        const char *tail;

        if (strncmp(path, bases[i], blen) != 0)
            continue;
        tail = path + blen;
        if (!tail[0])
            return 1;
        if (tail[0] != '/' || !tail[1] || strchr(tail + 1, '/'))
            return -1;
        if (!webd_safe_token(tail + 1))
            return -1;
        if (id && id_len) {
            if (strlen(tail + 1) >= id_len)
                return -1;
            snprintf(id, id_len, "%s", tail + 1);
        }
        return 2;
    }
    return 0;
}

struct json_object *webd_topology_port_profiles_response(const struct http_req *req,
                                                                struct json_object *body,
                                                                int *http_status)
{
    char id[128] = "";
    int match = webd_port_profiles_path(req ? req->path : "", id, sizeof(id));
    struct json_object *params = NULL;
    struct json_object *resp = NULL;

    if (http_status)
        *http_status = 200;
    if (match < 0) {
        if (http_status)
            *http_status = 400;
        return webd_error("invalid_port_profile_path", "invalid port profile path or id",
                          "id", "webd.port_profiles");
    }
    if (!req || !req->method[0] || match == 0) {
        if (http_status)
            *http_status = 404;
        return webd_error("port_profiles_not_found", "port profiles path not found",
                          "path", "webd.port_profiles");
    }

    if (!strcmp(req->method, "GET") && match == 1) {
        resp = app_ubus_invoke_timeout("physical_port_profile_list", NULL, 3000);
    } else if (!strcmp(req->method, "GET") && match == 2) {
        params = json_object_new_object();
        json_object_object_add(params, "id", json_object_new_string(id));
        resp = app_ubus_invoke_timeout("physical_port_profile_get", params, 3000);
        json_object_put(params);
    } else if ((!strcmp(req->method, "POST") || !strcmp(req->method, "PUT")) &&
               (match == 1 || match == 2)) {
        struct json_object *existing = NULL;

        params = body ? json_object_get(body) : json_object_new_object();
        if (match == 2 && params) {
            if (json_object_object_get_ex(params, "id", &existing) && existing &&
                (!json_object_is_type(existing, json_type_string) ||
                 strcmp(json_object_get_string(existing), id))) {
                json_object_put(params);
                if (http_status)
                    *http_status = 409;
                return webd_error("port_profile_id_conflict",
                                  "port profile path id and body id must match",
                                  id, "webd.port_profiles");
            }
            if (!existing)
                json_object_object_add(params, "id", json_object_new_string(id));
        }
        resp = app_ubus_invoke_timeout("physical_port_profile_set", params, 5000);
        json_object_put(params);
        if (app_ubus_response_ok(resp)) {
            jmx_cache_invalidate("network_ports");
            jmx_cache_invalidate("topology_unifi");
            webd_topology_infrastructure_cache_invalidate();
        }
    } else if (!strcmp(req->method, "DELETE") && match == 2) {
        params = json_object_new_object();
        json_object_object_add(params, "id", json_object_new_string(id));
        resp = app_ubus_invoke_timeout("physical_port_profile_delete", params, 5000);
        json_object_put(params);
        if (app_ubus_response_ok(resp)) {
            jmx_cache_invalidate("network_ports");
            jmx_cache_invalidate("topology_unifi");
            webd_topology_infrastructure_cache_invalidate();
        }
    } else {
        if (http_status)
            *http_status = 405;
        return webd_error("method_not_allowed", "method not allowed for port profiles",
                          req->method, "webd.port_profiles");
    }
    if (!resp) {
        if (http_status)
            *http_status = 503;
        return webd_error("source_unavailable", "physical port profile source is unavailable",
                          "dreamingwrt physical_port_profile_*", "webd.port_profiles");
    }
    if (http_status) {
        *http_status = app_jmx_response_http_status(resp, *http_status);
        if (*http_status == 400) {
            struct json_object *response_data = webd_obj_child_obj(resp, "data");
            if (!strcmp(app_nc_json_str(response_data, "error", ""), "profile_in_use"))
                *http_status = 409;
            else if (!strcmp(app_nc_json_str(response_data, "error", ""),
                             "invalid_or_protected_profile_id") &&
                     app_nc_json_bool(response_data, "protected", 0))
                *http_status = 409;
        }
    }
    return resp;
}

struct json_object *webd_topology_port_plan_response(const struct http_req *req,
                                                           struct json_object *body,
                                                           int apply,
                                                           const char *device_id,
                                                           int *http_status)
{
    char ifname[128] = "";
    char target_owner_type[32] = "";
    char target_owner_id[128] = "";
    const char *owner_type;
    const char *owner_id;
    struct json_object *root = json_object_new_object();
    struct json_object *plan = json_object_new_object();
    struct json_object *unsupported = json_object_new_array();
    struct json_object *unsupported_details = json_object_new_array();
    struct json_object *warnings = json_object_new_array();
    struct json_object *port = NULL;
    int enabled_present = 0;
    int enabled_value = 1;
    int requested_field_count = 0;
    int supported_write_count = 0;
    int speed_present = 0;
    int duplex_present = 0;
    int autoneg_present = 0;
    int vlan_profile_present = 0;
    int display_metadata_present = 0;
    int can_apply = 1;
    int requires_confirm = 0;
    int confirmed = app_nc_json_bool(body, "confirm", 0);
    int ok = 1;
    int owner_migration_requested = 0;

    if (http_status)
        *http_status = 200;
    webd_port_plan_fill_request(req, body, ifname, sizeof(ifname),
                                target_owner_type, sizeof(target_owner_type),
                                target_owner_id, sizeof(target_owner_id),
                                &enabled_present, &enabled_value);
    if (!ifname[0] || !webd_safe_token(ifname)) {
        if (http_status)
            *http_status = 400;
        json_object_put(root);
        json_object_put(plan);
        json_object_put(unsupported);
        json_object_put(unsupported_details);
        json_object_put(warnings);
        return webd_error("invalid_port_ifname", "port ifname is required and must be safe",
                          "ifname", "webd.topology_port_manager");
    }
    port = webd_physical_port_find(ifname);
    if (!port) {
        if (http_status)
            *http_status = 404;
        json_object_put(root);
        json_object_put(plan);
        json_object_put(unsupported);
        json_object_put(unsupported_details);
        json_object_put(warnings);
        return webd_error("port_not_found", "physical port was not found",
                          ifname, "webd.topology_port_manager");
    }
    requested_field_count = webd_port_plan_add_unsupported_from_body(body, unsupported, unsupported_details, port);

    owner_type = app_nc_json_str(port, "owner_type", "");
    owner_id = app_nc_json_str(port, "owner_id", "");
    if (!target_owner_type[0])
        snprintf(target_owner_type, sizeof(target_owner_type), "%s", owner_type);
    if (!target_owner_id[0])
        snprintf(target_owner_id, sizeof(target_owner_id), "%s", owner_id);

    if ((target_owner_type[0] && strcmp(target_owner_type, owner_type)) ||
        (target_owner_id[0] && strcmp(target_owner_id, owner_id))) {
        can_apply = 0;
        owner_migration_requested = 1;
        requires_confirm = 1;
        webd_port_plan_add_unsupported_detail(unsupported, unsupported_details, "owner",
                                              "port_reassignment", "transactional_multi_owner_apply_not_implemented", port);
        webd_array_add_unique_str(unsupported, "port_reassignment_apply");
        json_object_array_add(warnings, json_object_new_string("moving_ports_between_wan_lan_requires_transactional_multi_owner_apply"));
        json_object_array_add(warnings, json_object_new_string("port_reassignment_preview_only"));
    }
    webd_port_plan_add_supported_ops(plan, body, port, warnings,
                                     &supported_write_count,
                                     &speed_present, &duplex_present,
                                     &autoneg_present, &vlan_profile_present,
                                     &display_metadata_present);
    if (strcmp(owner_type, "wan") && strcmp(owner_type, "lan") &&
        !(display_metadata_present && supported_write_count == 1 && !enabled_present)) {
        can_apply = 0;
        webd_port_plan_add_unsupported_detail(unsupported, unsupported_details, "owner_type",
                                              "owner_type", "only_existing_wan_or_lan_owner_can_be_modified", port);
        json_object_array_add(warnings, json_object_new_string("only_existing_wan_or_lan_owner_can_be_modified"));
    }
    if (!enabled_present && supported_write_count == 0 && !owner_migration_requested) {
        can_apply = 0;
        json_object_array_add(warnings, json_object_new_string("no_supported_write_field_present"));
    }
    if (json_object_array_length(unsupported) > 0)
        can_apply = 0;
    if (!strcmp(owner_type, "wan") && enabled_present && !enabled_value) {
        requires_confirm = 1;
        json_object_array_add(warnings, json_object_new_string("disabling_wan_can_disconnect_internet"));
    }
    if (!strcmp(owner_type, "lan") && enabled_present && !enabled_value) {
        requires_confirm = 1;
        json_object_array_add(warnings, json_object_new_string("disabling_lan_can_disconnect_management_clients"));
    }
    if ((speed_present || duplex_present || autoneg_present) &&
        (!strcmp(owner_type, "wan") || !strcmp(owner_type, "lan"))) {
        requires_confirm = 1;
        json_object_array_add(warnings, json_object_new_string("changing_port_speed_or_duplex_can_drop_link_temporarily"));
    }
    if (vlan_profile_present) {
        requires_confirm = 1;
        json_object_array_add(warnings, json_object_new_string("changing_vlan_profile_uses_guarded_network_transaction"));
    }

    json_object_object_add(plan, "operation", json_object_new_string(owner_migration_requested ?
                                                                      "port_reassignment_preview" :
                                                                      (supported_write_count > 0 && enabled_present ?
                                                                       "set_port_enabled_and_config" :
                                                                       (supported_write_count > 0 ? "set_port_config" :
                                                                        "set_port_enabled"))));
    json_object_object_add(plan, "ifname", json_object_new_string(ifname));
    json_object_object_add(plan, "current_port", json_object_get(port));
    json_object_object_add(plan, "current_owner_type", json_object_new_string(owner_type));
    json_object_object_add(plan, "current_owner_id", json_object_new_string(owner_id));
    json_object_object_add(plan, "target_owner_type", json_object_new_string(target_owner_type));
    json_object_object_add(plan, "target_owner_id", json_object_new_string(target_owner_id));
    json_object_object_add(plan, "enabled_present", json_object_new_boolean(enabled_present));
    json_object_object_add(plan, "target_enabled", json_object_new_boolean(enabled_value));
    json_object_object_add(plan, "requested_field_count", json_object_new_int(requested_field_count));
    json_object_object_add(plan, "supported_write_count", json_object_new_int(supported_write_count));
    json_object_object_add(plan, "speed_present", json_object_new_boolean(speed_present));
    json_object_object_add(plan, "duplex_present", json_object_new_boolean(duplex_present));
    json_object_object_add(plan, "autoneg_present", json_object_new_boolean(autoneg_present));
    json_object_object_add(plan, "vlan_profile_present", json_object_new_boolean(vlan_profile_present));
    json_object_object_add(plan, "display_metadata_present", json_object_new_boolean(display_metadata_present));
    json_object_object_add(plan, "owner_migration_requested", json_object_new_boolean(owner_migration_requested));
    if (owner_migration_requested)
        json_object_object_add(plan, "migration_plan",
                               webd_port_migration_plan(ifname, port, body, owner_type, owner_id,
                                                        target_owner_type, target_owner_id));
    if (vlan_profile_present)
        json_object_object_add(plan, "vlan_runtime_plan",
                               webd_port_vlan_runtime_plan(ifname, body, port));
    json_object_object_add(plan, "can_apply", json_object_new_boolean(can_apply));
    json_object_object_add(plan, "requires_confirm", json_object_new_boolean(requires_confirm));
    json_object_object_add(plan, "unsupported", json_object_get(unsupported));
    json_object_object_add(plan, "unsupported_details", json_object_get(unsupported_details));
    json_object_object_add(plan, "warnings", json_object_get(warnings));
    json_object_object_add(plan, "transaction_preview",
                           webd_port_transaction_preview_from_plan(plan, body, device_id));

    json_object_object_add(root, "ok", json_object_new_boolean(can_apply || !apply));
    json_object_object_add(root, "preview", json_object_new_boolean(!apply));
    json_object_object_add(root, "applied", json_object_new_boolean(0));
    json_object_object_add(root, "plan", plan);
    json_object_object_add(root, "capabilities", webd_topology_port_write_capabilities(port));
    if (apply) {
        struct json_object *params = NULL;
        struct json_object *apply_resp = NULL;
        const char *method = NULL;

        if (!can_apply) {
            ok = 0;
            if (http_status)
                *http_status = owner_migration_requested ? 409 : 400;
            json_object_object_add(root, "error",
                                   json_object_new_string(owner_migration_requested ?
                                                          "port_reassignment_transaction_pending" :
                                                          "port_write_not_supported_for_requested_fields"));
        } else if (vlan_profile_present || (requires_confirm && !confirmed)) {
            struct json_object *changes = json_object_new_object();
            struct json_object *tx_params = json_object_new_object();
            struct json_object *tx_resp = NULL;
            int rollback_timeout = app_nc_json_int(body, "rollback_timeout", 90);

            json_object_object_add(changes, "kind", json_object_new_string("port_manager_apply"));
            json_object_object_add(changes, "ifname", json_object_new_string(ifname));
            json_object_object_add(changes, "request", body ? json_object_get(body) : json_object_new_object());
            json_object_object_add(changes, "plan", json_object_get(plan));
            json_object_object_add(changes, "transaction_preview",
                                   webd_port_transaction_preview_from_plan(plan, body, device_id));
            json_object_object_add(changes, "actor", json_object_new_string(device_id && device_id[0] ? device_id : "web"));
            json_object_object_add(changes, "created_by_endpoint",
                                   json_object_new_string("/api/v1/topology/node/ports/apply"));
            json_object_object_add(tx_params, "scope", json_object_new_string("topology.port_manager"));
            json_object_object_add(tx_params, "snapshot", json_object_new_boolean(1));
            json_object_object_add(tx_params, "rollback_timeout", json_object_new_int(rollback_timeout));
            json_object_object_add(tx_params, "changes", changes);
            webd_json_copy_key(tx_params, "idempotency_key", body, "idempotency_key");
            webd_json_copy_key(tx_params, "expected_base_digest", body, "expected_base_digest");
            webd_json_copy_key(tx_params, "expected_port_revision", body, "expected_port_revision");
            tx_resp = jmx_config_apply(tx_params);
            json_object_put(tx_params);

            if (tx_resp && app_nc_json_bool(tx_resp, "ok", 0)) {
                struct json_object *confirm_resp = NULL;

                if (confirmed && vlan_profile_present) {
                    struct json_object *confirm_params = json_object_new_object();
                    json_object_object_add(confirm_params, "task_id",
                                           json_object_new_int(app_nc_json_int(tx_resp, "task_id", 0)));
                    confirm_resp = jmx_config_confirm(confirm_params);
                    json_object_put(confirm_params);
                }
                ok = 1;
                if (http_status)
                    *http_status = (confirmed && vlan_profile_present) ? 200 : 202;
                json_object_object_add(root, "transaction_created", json_object_new_boolean(1));
                json_object_object_add(root, "transaction_required", json_object_new_boolean(!(confirmed && vlan_profile_present)));
                json_object_object_add(root, "requires_confirm", json_object_new_boolean(!(confirmed && vlan_profile_present)));
                json_object_object_add(root, "applied", json_object_new_boolean(vlan_profile_present));
                json_object_object_add(root, "transaction", tx_resp);
                if (confirm_resp)
                    json_object_object_add(root, "confirm_response", confirm_resp);
                json_object_object_add(root, "transaction_preview",
                                       webd_port_transaction_preview_from_plan(plan, body, device_id));
                json_object_object_add(root, "next_action", json_object_new_string((confirmed && vlan_profile_present) ?
                                       "readback_verify_done" : "confirm_or_rollback"));
                json_object_object_add(root, "warning",
                                       json_object_new_string(vlan_profile_present ?
                                       "guarded_vlan_runtime_transaction_applied" :
                                       "high_risk_port_change_pending_transaction_created_no_live_mutation"));
            } else {
                ok = 0;
                if (http_status)
                    *http_status = 409;
                json_object_object_add(root, "error", json_object_new_string(tx_resp ?
                                       app_nc_json_str(tx_resp, "error", "confirmation_required") :
                                       "confirmation_required"));
                if (tx_resp)
                    json_object_object_add(root, "transaction_error", tx_resp);
            }
        } else {
            struct json_object *event = NULL;
            struct json_object *detail = NULL;

            ok = 1;
            if (enabled_present) {
                params = json_object_new_object();
                json_object_object_add(params, "id", json_object_new_string(owner_id));
                json_object_object_add(params, "enabled", json_object_new_boolean(enabled_value));
                method = !strcmp(owner_type, "wan") ? "wan_enable" : "lan_enable";
                apply_resp = app_ubus_invoke_timeout(method, params, 10000);
                json_object_put(params);
                if (!apply_resp) {
                    ok = 0;
                    if (http_status)
                        *http_status = 503;
                    json_object_object_add(root, "error", json_object_new_string("owner_apply_unavailable"));
                } else {
                    ok = app_ubus_response_ok(apply_resp);
                    json_object_object_add(root, "owner_method", json_object_new_string(method));
                    json_object_object_add(root, "owner_upstream", apply_resp);
                    if (!ok) {
                        if (http_status)
                            *http_status = 400;
                        json_object_object_add(root, "error", json_object_new_string("owner_apply_failed"));
                    }
                    apply_resp = NULL;
                }
            }

            if (ok && supported_write_count > 0) {
                struct json_object *cfg = json_object_new_object();
                struct json_object *tagged = NULL;
                char duplex_norm[16] = "";
                int an_present = 0;
                int an = webd_port_request_autoneg(body, &an_present);

                json_object_object_add(cfg, "ifname", json_object_new_string(ifname));
                if (speed_present)
                    json_object_object_add(cfg, "speed_mbps", json_object_new_int(webd_port_request_speed(body)));
                if (duplex_present) {
                    webd_normalize_duplex_value(app_nc_json_str(body, "duplex",
                        app_nc_json_str(body, "configured_duplex", "")), duplex_norm, sizeof(duplex_norm));
                    json_object_object_add(cfg, "duplex", json_object_new_string(duplex_norm));
                }
                if (autoneg_present)
                    json_object_object_add(cfg, "configured_autoneg", json_object_new_int(an));
                if (vlan_profile_present) {
                    if (app_nc_json_has(body, "native_vlan") || app_nc_json_has(body, "vlan_id"))
                        json_object_object_add(cfg, "native_vlan", json_object_new_int(app_nc_json_int(body, "native_vlan", app_nc_json_int(body, "vlan_id", 0))));
                    if (app_nc_json_has(body, "profile_id") || app_nc_json_has(body, "profile"))
                        json_object_object_add(cfg, "profile_id", json_object_new_string(app_nc_json_str(body, "profile_id", app_nc_json_str(body, "profile", ""))));
                    if (webd_port_request_tagged_vlans(body, &tagged) > 0)
                        json_object_object_add(cfg, "tagged_vlans", json_object_get(tagged));
                }
                if (display_metadata_present) {
                    if (app_nc_json_has(body, "display_name") || app_nc_json_has(body, "alias"))
                        json_object_object_add(cfg, "display_name", json_object_new_string(
                            app_nc_json_str(body, "display_name", app_nc_json_str(body, "alias", ""))));
                    if (app_nc_json_has(body, "sort_order"))
                        json_object_object_add(cfg, "sort_order", json_object_new_int(
                            app_nc_json_int(body, "sort_order", 0)));
                }
                apply_resp = app_ubus_invoke_timeout("physical_port_config_apply", cfg, 10000);
                json_object_put(cfg);
                if (!apply_resp) {
                    ok = 0;
                    if (http_status)
                        *http_status = 503;
                    json_object_object_add(root, "error", json_object_new_string("port_config_apply_unavailable"));
                } else {
                    ok = app_ubus_response_ok(apply_resp);
                    json_object_object_add(root, "port_config_upstream", apply_resp);
                    if (!ok) {
                        if (http_status)
                            *http_status = 400;
                        json_object_object_add(root, "error", json_object_new_string("port_config_apply_failed"));
                    }
                    apply_resp = NULL;
                }
            }

            json_object_object_add(root, "applied", json_object_new_boolean(ok));
            if (ok) {
                struct json_object *readback = webd_port_post_apply_readback(ifname,
                                                                             speed_present,
                                                                             duplex_present,
                                                                             autoneg_present,
                                                                             vlan_profile_present,
                                                                             display_metadata_present);
                event = json_object_new_object();
                detail = json_object_new_object();

                jmx_cache_invalidate("network_ports");
                jmx_cache_invalidate("network_overview");
                jmx_cache_invalidate("network_wans");
                jmx_cache_invalidate("topology_unifi");
                webd_topology_infrastructure_cache_invalidate();
                json_object_object_add(detail, "ifname", json_object_new_string(ifname));
                json_object_object_add(detail, "owner_type", json_object_new_string(owner_type));
                json_object_object_add(detail, "owner_id", json_object_new_string(owner_id));
                json_object_object_add(detail, "enabled_present", json_object_new_boolean(enabled_present));
                json_object_object_add(detail, "enabled", json_object_new_boolean(enabled_value));
                json_object_object_add(detail, "speed_present", json_object_new_boolean(speed_present));
                json_object_object_add(detail, "duplex_present", json_object_new_boolean(duplex_present));
                json_object_object_add(detail, "autoneg_present", json_object_new_boolean(autoneg_present));
                json_object_object_add(detail, "vlan_profile_present", json_object_new_boolean(vlan_profile_present));
                json_object_object_add(detail, "display_metadata_present", json_object_new_boolean(display_metadata_present));
                if (display_metadata_present) {
                    json_object_object_add(detail, "display_name", json_object_new_string(
                        app_nc_json_str(body, "display_name", app_nc_json_str(body, "alias", ""))));
                    json_object_object_add(detail, "sort_order", json_object_new_int(
                        app_nc_json_int(body, "sort_order", 0)));
                }
                json_object_object_add(detail, "post_apply_readback_ok",
                                       json_object_new_boolean(app_nc_json_bool(readback, "ok", 0)));
                json_object_object_add(detail, "post_apply_readback_reason",
                                       json_object_new_string(app_nc_json_str(readback, "reason", "")));
                json_object_object_add(detail, "actor", json_object_new_string(device_id && device_id[0] ? device_id : "web"));
                /* Explicit admin-audit marker so this real operation stays in the
                 * ledger once the classifier stops trusting bare category='audit'
                 * (which legacy daemon auth lines also carried). */
                json_object_object_add(detail, "source_id", json_object_new_string("audit"));
                json_object_object_add(detail, "web_audit", json_object_new_boolean(1));
                json_object_object_add(event, "event", json_object_new_string("port_config_updated"));
                json_object_object_add(event, "severity", json_object_new_string("warning"));
                json_object_object_add(event, "category", json_object_new_string("audit"));
                json_object_object_add(event, "source", json_object_new_string("dreamingwrt-webd"));
                json_object_object_add(event, "title", json_object_new_string("Port configuration updated"));
                json_object_object_add(event, "detail", detail);
                json_object_object_add(root, "post_apply_readback", readback);
                {
                    struct json_object *event_resp =
                        app_ubus_invoke_object_timeout("dreamingwrt.logd", "event_add", event, 500);
                    if (event_resp)
                        json_object_put(event_resp);
                }
                json_object_put(event);
            }
        }
        json_object_object_add(root, "ok", json_object_new_boolean(ok));
    }

    json_object_object_add(root, "unsupported", unsupported);
    json_object_object_add(root, "unsupported_details", unsupported_details);
    json_object_object_add(root, "warnings", warnings);
    if (port)
        json_object_put(port);
    return webd_envelope(root, apply ? "webd.topology_port_manager_apply" : "webd.topology_port_manager_preview");
}

static struct json_object *webd_port_vlan_error(int code, const char *reason, int *status)
{
    struct json_object *result = json_object_new_object();
    *status = code;
    json_object_object_add(result, "ok", json_object_new_boolean(0));
    json_object_object_add(result, "valid", json_object_new_boolean(0));
    json_object_object_add(result, "code", json_object_new_int(code));
    json_object_object_add(result, "error", json_object_new_string(reason));
    return result;
}

struct json_object *webd_port_vlan_resources(void)
{
    struct json_object *upstream = app_ubus_invoke_timeout("physical_port_list", NULL, 2000);
    struct json_object *data = webd_data_or_self_from_jmx_response(upstream);
    struct json_object *ports = webd_obj_child_array(data, "ports");
    struct json_object *result = json_object_new_array();
    size_t i;
    for (i = 0; ports && i < json_object_array_length(ports); i++) {
        struct json_object *port = json_object_array_get_idx(ports, i);
        const char *id = app_nc_json_str(port, "ifname", app_nc_json_str(port, "name", ""));
        struct json_object *row;
        if (!webd_port_ifname_strict_ok(id)) continue;
        row = json_object_new_object();
        json_object_object_add(row, "id", json_object_new_string(id));
        json_object_object_add(row, "name", json_object_new_string(
            app_nc_json_str(port, "display_name", id)));
        json_object_array_add(result, row);
    }
    json_object_put(data);
    json_object_put(upstream);
    return result;
}

/* Read UCI membership, not DB defaults: a saved native_vlan=0 does not mean
 * the live bridge has no native VLAN. Unsupported shapes remain read-only. */
static const char *webd_port_vlan_read_config(struct uci_context *ctx,
                                             const char *ifname, const char *bridge,
                                             struct json_object *config)
{
    struct uci_package *pkg = NULL;
    struct uci_element *e;
    struct json_object *tagged = json_object_new_array();
    const char *reason = "";
    int native = 0, filtering = 0;
    if (!ctx || uci_load(ctx, "network", &pkg) != UCI_OK) {
        reason = "network_config_unavailable";
        goto done;
    }
    uci_foreach_element(&pkg->sections, e) {
        struct uci_section *s = uci_to_section(e);
        const char *device = uci_lookup_option_string(ctx, s, "device");
        const char *name = uci_lookup_option_string(ctx, s, "name");
        const char *vlan;
        struct uci_option *ports;
        struct uci_element *pe;
        int vid;
        if (!strcmp(s->type, "device") && name && !strcmp(name, bridge)) {
            const char *value = uci_lookup_option_string(ctx, s, "vlan_filtering");
            filtering = value && !strcmp(value, "1");
        }
        if (strcmp(s->type, "bridge-vlan") || !device || strcmp(device, bridge))
            continue;
        vlan = uci_lookup_option_string(ctx, s, "vlan");
        vid = vlan ? atoi(vlan) : 0;
        ports = uci_lookup_option(ctx, s, "ports");
        if (!ports) continue;
        if (ports->type != UCI_TYPE_LIST) {
            reason = "vlan_membership_format_unsupported";
            continue;
        }
        uci_foreach_element(&ports->v.list, pe) {
            const char *flags;
            size_t len = strlen(ifname);
            if (strncmp(pe->name, ifname, len) ||
                (pe->name[len] && pe->name[len] != ':')) continue;
            flags = pe->name + len;
            if (!webd_port_vlan_id_ok(vid, 0)) {
                reason = "invalid_configured_vlan";
            } else if (!strcmp(flags, ":t")) {
                if (!webd_json_array_contains_int_value(tagged, vid))
                    json_object_array_add(tagged, json_object_new_int(vid));
            } else if (!strcmp(flags, ":u*") || !strcmp(flags, ":*") || !flags[0]) {
                if (native && native != vid) reason = "multiple_native_vlans_unsupported";
                native = vid;
            } else {
                reason = "vlan_membership_flags_unsupported";
            }
        }
    }
    if (!filtering && !reason[0]) reason = "bridge_vlan_filtering_not_enabled";
done:
    json_object_object_add(config, "native_vlan", json_object_new_int(native));
    json_object_object_add(config, "tagged_vlans", tagged);
    if (pkg) uci_unload(ctx, pkg);
    return reason;
}

struct json_object *webd_port_vlan_snapshot(const char *ifname, int *http_status)
{
    struct json_object *port, *config, *result, *stp;
    const char *bridge, *reason = "";
    struct uci_context *ctx;
    char revision[72], after[72], path[256], phys[128];
    if (!webd_port_ifname_strict_ok(ifname))
        return webd_port_vlan_error(400, "invalid_ifname", http_status);
    port = webd_physical_port_find(ifname);
    if (!port) return webd_port_vlan_error(404, "port_not_found", http_status);
    if (safeops_port_revision(g_config_db, WEBD_NETWORK_CONFIG_PATH, ifname, revision) != 0) {
        json_object_put(port);
        return webd_port_vlan_error(503, "port_revision_unavailable", http_status);
    }
    stp = webd_obj_child_obj(port, "stp");
    bridge = app_nc_json_str(stp, "bridge", "");
    config = json_object_new_object();
    json_object_object_add(config, "bridge", json_object_new_string(bridge));
    ctx = uci_alloc_context();
    reason = webd_port_vlan_read_config(ctx, ifname, bridge, config);
    if (ctx) uci_free_context(ctx);
    snprintf(path, sizeof(path), "/sys/class/net/%s/brport", ifname);
    if (access(path, F_OK) != 0 || !webd_port_uci_section_strict_ok(bridge)) {
        reason = "not_a_linux_bridge_port";
    } else {
        snprintf(path, sizeof(path), "/sys/class/net/%s/dsa", ifname);
        if (access(path, F_OK) != 0) {
            snprintf(path, sizeof(path), "/sys/class/net/%s/phys_port_name", ifname);
            if (webd_file_read_first_line(path, phys, sizeof(phys)) != 0 || !phys[0])
                reason = "not_dsa_or_no_phys_port_name";
        }
    }
    if (strcmp(app_nc_json_str(port, "owner_type", ""), "lan"))
        reason = "vlan_requires_existing_lan_owner";
    if (!webd_bridge_cmd_path()[0] && !reason[0]) reason = "bridge_tool_unavailable";
    if (safeops_port_revision(g_config_db, WEBD_NETWORK_CONFIG_PATH, ifname, after) != 0 ||
        strcmp(after, revision)) {
        json_object_put(port);
        json_object_put(config);
        return webd_port_vlan_error(409, "configuration_changed_during_read", http_status);
    }
    result = json_object_new_object();
    json_object_object_add(result, "ok", json_object_new_boolean(1));
    json_object_object_add(result, "domain", json_object_new_string("vlan"));
    json_object_object_add(result, "id", json_object_new_string(ifname));
    json_object_object_add(result, "config", config);
    json_object_object_add(result, "revision", json_object_new_string(revision));
    json_object_object_add(result, "write_supported", json_object_new_boolean(!reason[0]));
    json_object_object_add(result, "unavailable_reason", json_object_new_string(reason));
    json_object_object_add(result, "apply_executor", json_object_new_string("dsa_bridge_vlan_uci_reload_guarded"));
    json_object_object_add(result, "readback_source", json_object_new_string("uci_bridge_vlan_membership"));
    json_object_object_add(result, "runtime_verified", json_object_new_boolean(0));
    json_object_put(port);
    *http_status = 200;
    return result;
}

struct json_object *webd_port_vlan_request(const struct http_req *req,
                                         struct json_object *body, int apply,
                                         int *http_status)
{
    const char *ifname = app_nc_json_str(body, "id", "");
    const char *revision = app_nc_json_str(body, "if_revision", "");
    const char *key = app_nc_json_str(body, "idempotency_key", "");
    struct json_object *snapshot, *config, *patch, *request, *response, *data, *plan;
    const char *error = NULL;
    int code = 400, changed = 0, native;
    size_t i, j;
    if (apply && key[0]) {
        sqlite3_stmt *st = NULL;
        int task_id = 0;
        if (sqlite3_prepare_v2(g_app_db,
            "SELECT id FROM config_apply_tasks WHERE idempotency_key=?1 ORDER BY id DESC LIMIT 1",
            -1, &st, NULL) != SQLITE_OK)
            return webd_port_vlan_error(503, "transaction_lookup_unavailable", http_status);
        sqlite3_bind_text(st, 1, key, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) == SQLITE_ROW) task_id = sqlite3_column_int(st, 0);
        sqlite3_finalize(st);
        if (task_id) {
            *http_status = 200;
            response = jmx_tasks_get(task_id);
            json_object_object_add(response, "idempotent_replay", json_object_new_boolean(1));
            return response;
        }
    }
    snapshot = webd_port_vlan_snapshot(ifname, http_status);
    if (*http_status != 200) return snapshot;
    config = webd_obj_child_obj(snapshot, "config");
    patch = webd_obj_child_obj(body, "config");
    if (!revision[0]) { error = "revision_required"; code = 428; }
    else if (strcmp(revision, app_nc_json_str(snapshot, "revision", ""))) {
        error = "revision_conflict"; code = 409;
    } else if (!app_nc_json_bool(snapshot, "write_supported", 0)) {
        error = app_nc_json_str(snapshot, "unavailable_reason", "vlan_write_unavailable"); code = 409;
    } else if (!patch || !json_object_object_length(patch)) {
        error = "empty_patch";
    }
    request = webd_json_clone(config);
    if (!error) {
        json_object_object_foreach(patch, field, value) {
            if (strcmp(field, "native_vlan") && strcmp(field, "tagged_vlans")) {
                error = "unsupported_vlan_field"; break;
            }
            if (!json_object_equal(value, json_object_object_get(config, field))) changed = 1;
            json_object_object_add(request, field, json_object_get(value));
        }
    }
    native = app_nc_json_int(request, "native_vlan", 0);
    if (!error) {
        struct json_object *value = json_object_object_get(request, "native_vlan");
        struct json_object *tagged = webd_obj_child_array(request, "tagged_vlans");
        if (!json_object_is_type(value, json_type_int) || !webd_port_vlan_id_ok(native, 0))
            error = "invalid_native_vlan";
        else if (!tagged || json_object_array_length(tagged) > 128) error = "invalid_tagged_vlans";
        for (i = 0; !error && i < json_object_array_length(tagged); i++) {
            value = json_object_array_get_idx(tagged, i);
            int vid = json_object_get_int(value);
            if (!json_object_is_type(value, json_type_int) || !webd_port_vlan_id_ok(vid, 0) || vid == native)
                error = "invalid_tagged_vlan";
            for (j = 0; !error && j < i; j++)
                if (vid == json_object_get_int(json_object_array_get_idx(tagged, j)))
                    error = "duplicate_tagged_vlan";
        }
        if (!error && !changed) error = "no_changes";
    }
    if (!error && apply && (!key[0] || strlen(key) > 128 ||
        !app_nc_json_bool(body, "confirm_risk", 0)))
        error = "idempotency_key_and_risk_consent_required";
    if (!error && apply && (app_nc_json_int(body, "rollback_timeout", 90) < 60 ||
                           app_nc_json_int(body, "rollback_timeout", 90) > 3600))
        error = "invalid_rollback_timeout";
    if (error) {
        response = webd_port_vlan_error(code, error, http_status);
        json_object_object_add(response, "canonical", snapshot);
        json_object_put(request);
        return response;
    }
    json_object_object_add(request, "ifname", json_object_new_string(ifname));
    json_object_object_add(request, "expected_port_revision", json_object_new_string(revision));
    json_object_object_add(request, "idempotency_key", json_object_new_string(key));
    json_object_object_add(request, "rollback_timeout", json_object_new_int(app_nc_json_int(body, "rollback_timeout", 90)));
    /* Risk consent is not retention confirmation. Never pass confirm=true. */
    response = webd_topology_port_plan_response(req, request, apply, "config.vlan", http_status);
    data = webd_data_or_self_from_jmx_response(response);
    plan = webd_obj_child_obj(data, "plan");
    if (!apply) {
        int valid = app_nc_json_bool(plan, "can_apply", 0);
        json_object_put(response);
        response = json_object_new_object();
        json_object_object_add(response, "ok", json_object_new_boolean(1));
        json_object_object_add(response, "valid", json_object_new_boolean(valid));
        if (plan) json_object_object_add(response, "plan", json_object_get(plan));
    } else {
        struct json_object *tx = webd_obj_child_obj(data, "transaction");
        if (tx) {
            struct json_object *task = jmx_tasks_get(app_nc_json_int(tx, "task_id", 0));
            json_object_put(response);
            response = task;
        } else if (!app_nc_json_bool(data, "ok", 0)) {
            struct json_object *failure = webd_port_vlan_error(*http_status,
                app_nc_json_str(data, "error", "vlan_apply_failed"), http_status);
            json_object_object_add(failure, "detail", response);
            response = failure;
        }
    }
    json_object_put(data);
    json_object_put(request);
    json_object_put(snapshot);
    return response;
}

static struct json_object *webd_port_batch_item_request(struct json_object *item,
                                                         struct json_object *common,
                                                         const char *ifname)
{
    struct json_object *request = common ? webd_json_clone(common) : json_object_new_object();

    if (!request || !json_object_is_type(request, json_type_object)) {
        if (request)
            json_object_put(request);
        request = json_object_new_object();
    }
    if (item && json_object_is_type(item, json_type_object)) {
        json_object_object_foreach(item, key, value) {
            if (!strcmp(key, "changes"))
                continue;
            json_object_object_add(request, key, json_object_get(value));
        }
        {
            struct json_object *changes = webd_obj_child_obj(item, "changes");
            if (changes) {
                json_object_object_foreach(changes, key, value) {
                    json_object_object_add(request, key, json_object_get(value));
                }
            }
        }
    }
    json_object_object_add(request, "ifname", json_object_new_string(ifname ? ifname : ""));
    return request;
}

struct json_object *webd_topology_port_batch_response(const struct http_req *req,
                                                             struct json_object *body,
                                                             int apply,
                                                             const char *device_id,
                                                             int *http_status)
{
    struct json_object *items = webd_obj_child_array(body, "items");
    struct json_object *ifnames = webd_obj_child_array(body, "ifnames");
    struct json_object *common = webd_obj_child_obj(body, "changes");
    struct json_object *requests = json_object_new_array();
    struct json_object *previews = json_object_new_array();
    struct json_object *results = json_object_new_array();
    struct json_object *data = json_object_new_object();
    char seen[WEBD_PORT_BATCH_MAX][IFNAMSIZ];
    int n, i, j;
    int ready = 1;
    int confirm_required = 0;
    int confirmed = app_nc_json_bool(body, "confirm", 0);
    int stop_on_error = app_nc_json_bool(body, "stop_on_error", 1);
    int succeeded = 0, failed = 0, skipped = 0;
    int stopped = 0;

    if (http_status)
        *http_status = 200;
    if ((!items || !json_object_is_type(items, json_type_array)) &&
        (!ifnames || !json_object_is_type(ifnames, json_type_array))) {
        json_object_put(requests);
        json_object_put(previews);
        json_object_put(results);
        json_object_put(data);
        if (http_status)
            *http_status = 400;
        return webd_error("invalid_port_batch", "items or ifnames array is required",
                          "items|ifnames", "webd.topology_port_batch");
    }
    n = items ? (int)json_object_array_length(items) :
                (int)json_object_array_length(ifnames);
    if (n <= 0 || n > WEBD_PORT_BATCH_MAX) {
        json_object_put(requests);
        json_object_put(previews);
        json_object_put(results);
        json_object_put(data);
        if (http_status)
            *http_status = 400;
        return webd_error("invalid_port_batch_size", "port batch must contain 1 to 64 ports",
                          "1..64", "webd.topology_port_batch");
    }

    for (i = 0; i < n; i++) {
        struct json_object *item = items ? json_object_array_get_idx(items, i) : NULL;
        struct json_object *ifname_value = ifnames ? json_object_array_get_idx(ifnames, i) : NULL;
        struct json_object *request;
        struct json_object *preview;
        struct json_object *preview_data;
        struct json_object *plan;
        const char *ifname = item && json_object_is_type(item, json_type_object) ?
                             app_nc_json_str(item, "ifname", app_nc_json_str(item, "port_id", "")) :
                             (ifname_value ? json_object_get_string(ifname_value) : "");
        int duplicate = 0;
        int item_status = 200;
        int can_apply = 0;

        for (j = 0; j < i; j++)
            if (ifname && !strcmp(seen[j], ifname))
                duplicate = 1;
        snprintf(seen[i], sizeof(seen[i]), "%s", ifname ? ifname : "");
        request = webd_port_batch_item_request(item, common, ifname);
        if (duplicate) {
            preview = webd_error("duplicate_port_ifname", "port appears more than once in batch",
                                 ifname, "webd.topology_port_batch");
            item_status = 400;
        } else {
            preview = webd_topology_port_plan_response(req, request, 0,
                                                       device_id, &item_status);
        }
        preview_data = webd_obj_child_obj(preview, "data");
        plan = webd_obj_child_obj(preview_data, "plan");
        can_apply = item_status < 400 && plan && app_nc_json_bool(plan, "can_apply", 0);
        if (plan && app_nc_json_bool(plan, "requires_confirm", 0))
            confirm_required = 1;
        if (!can_apply)
            ready = 0;
        {
            struct json_object *entry = json_object_new_object();
            json_object_object_add(entry, "ifname", json_object_new_string(ifname ? ifname : ""));
            json_object_object_add(entry, "valid", json_object_new_boolean(can_apply));
            json_object_object_add(entry, "http_status", json_object_new_int(item_status));
            json_object_object_add(entry, "response", preview);
            json_object_array_add(previews, entry);
        }
        if (confirmed)
            json_object_object_add(request, "confirm", json_object_new_boolean(1));
        json_object_array_add(requests, request);
    }

    if (apply && (!ready || (confirm_required && !confirmed))) {
        json_object_object_add(data, "ok", json_object_new_boolean(0));
        json_object_object_add(data, "applied", json_object_new_boolean(0));
        json_object_object_add(data, "ready", json_object_new_boolean(ready));
        json_object_object_add(data, "error", json_object_new_string(
            !ready ? "port_batch_preflight_failed" : "confirmation_required"));
        if (http_status)
            *http_status = 409;
    } else if (apply) {
        for (i = 0; i < n; i++) {
            struct json_object *request = json_object_array_get_idx(requests, i);
            struct json_object *result = json_object_new_object();
            const char *ifname = app_nc_json_str(request, "ifname", "");
            int item_status = 200;
            struct json_object *response = NULL;
            struct json_object *response_data;
            int ok;

            json_object_object_add(result, "ifname", json_object_new_string(ifname));
            if (stopped) {
                skipped++;
                json_object_object_add(result, "ok", json_object_new_boolean(0));
                json_object_object_add(result, "skipped", json_object_new_boolean(1));
                json_object_object_add(result, "error", json_object_new_string("stopped_after_error"));
                json_object_array_add(results, result);
                continue;
            }
            response = webd_topology_port_plan_response(req, request, 1,
                                                        device_id, &item_status);
            response_data = webd_obj_child_obj(response, "data");
            ok = item_status < 400 && response_data &&
                 app_nc_json_bool(response_data, "ok", 0);
            json_object_object_add(result, "ok", json_object_new_boolean(ok));
            json_object_object_add(result, "skipped", json_object_new_boolean(0));
            json_object_object_add(result, "http_status", json_object_new_int(item_status));
            json_object_object_add(result, "response", response);
            if (ok)
                succeeded++;
            else {
                failed++;
                if (stop_on_error)
                    stopped = 1;
            }
            json_object_array_add(results, result);
        }
        json_object_object_add(data, "ok", json_object_new_boolean(failed == 0));
        json_object_object_add(data, "applied", json_object_new_boolean(failed == 0));
        json_object_object_add(data, "ready", json_object_new_boolean(1));
        json_object_object_add(data, "partially_applied",
                               json_object_new_boolean(succeeded > 0 && (failed > 0 || skipped > 0)));
        if (failed > 0) {
            json_object_object_add(data, "error", json_object_new_string("port_batch_partial_apply_failed"));
            if (http_status)
                *http_status = 409;
        }
    } else {
        json_object_object_add(data, "ok", json_object_new_boolean(1));
        json_object_object_add(data, "applied", json_object_new_boolean(0));
        json_object_object_add(data, "ready", json_object_new_boolean(ready));
    }
    json_object_object_add(data, "preview", json_object_new_boolean(!apply));
    json_object_object_add(data, "atomic", json_object_new_boolean(0));
    json_object_object_add(data, "partial", json_object_new_boolean(1));
    json_object_object_add(data, "semantics",
                           json_object_new_string("ordered_single_port_transactions"));
    json_object_object_add(data, "stop_on_error", json_object_new_boolean(stop_on_error));
    json_object_object_add(data, "confirm_required", json_object_new_boolean(confirm_required));
    json_object_object_add(data, "max_ports", json_object_new_int(WEBD_PORT_BATCH_MAX));
    json_object_object_add(data, "count", json_object_new_int(n));
    json_object_object_add(data, "attempted", json_object_new_int(succeeded + failed));
    json_object_object_add(data, "succeeded", json_object_new_int(succeeded));
    json_object_object_add(data, "failed", json_object_new_int(failed));
    json_object_object_add(data, "skipped", json_object_new_int(skipped));
    json_object_object_add(data, "items", previews);
    json_object_object_add(data, "results", results);
    json_object_put(requests);
    return webd_envelope(data, apply ? "webd.topology_port_batch_apply" :
                                       "webd.topology_port_batch_preview");
}

struct json_object *webd_topology_port_transaction_validate_response(const struct http_req *req,
                                                                           struct json_object *body,
                                                                           int *http_status)
{
    char ifname[128] = "";
    char target_owner_type[32] = "";
    char target_owner_id[128] = "";
    const char *owner_type;
    const char *owner_id;
    struct json_object *root = json_object_new_object();
    struct json_object *port = NULL;
    struct json_object *warnings = json_object_new_array();
    struct json_object *validations = json_object_new_object();
    int enabled_present = 0;
    int enabled_value = 1;
    int vlan_requested;
    int owner_migration_requested;
    (void)target_owner_type;
    (void)enabled_present;
    (void)enabled_value;

    if (http_status)
        *http_status = 200;
    webd_port_plan_fill_request(req, body, ifname, sizeof(ifname),
                                target_owner_type, sizeof(target_owner_type),
                                target_owner_id, sizeof(target_owner_id),
                                &enabled_present, &enabled_value);
    if (!ifname[0] || !webd_safe_token(ifname)) {
        if (http_status)
            *http_status = 400;
        json_object_put(root);
        json_object_put(warnings);
        json_object_put(validations);
        return webd_error("invalid_port_ifname", "port ifname is required and must be safe",
                          "ifname", "webd.topology_port_transaction_validate");
    }
    port = webd_physical_port_find(ifname);
    if (!port) {
        if (http_status)
            *http_status = 404;
        json_object_put(root);
        json_object_put(warnings);
        json_object_put(validations);
        return webd_error("port_not_found", "physical port was not found",
                          ifname, "webd.topology_port_transaction_validate");
    }
    owner_type = app_nc_json_str(port, "owner_type", "");
    owner_id = app_nc_json_str(port, "owner_id", "");
    if (!target_owner_id[0])
        snprintf(target_owner_id, sizeof(target_owner_id), "%s", owner_id);
    vlan_requested = app_nc_json_has(body, "native_vlan") || app_nc_json_has(body, "vlan_id") ||
                     app_nc_json_has(body, "profile_id") || app_nc_json_has(body, "profile") ||
                     app_nc_json_has(body, "tagged_vlans");
    owner_migration_requested = target_owner_id[0] && strcmp(target_owner_id, owner_id);

    json_object_object_add(validations, "safe_token_ifname", json_object_new_boolean(webd_safe_token(ifname)));
    json_object_object_add(validations, "current_owner_type", json_object_new_string(owner_type));
    json_object_object_add(validations, "current_owner_id", json_object_new_string(owner_id));
    json_object_object_add(validations, "target_owner_id", json_object_new_string(target_owner_id));
    json_object_object_add(validations, "vlan_requested", json_object_new_boolean(vlan_requested));
    json_object_object_add(validations, "owner_migration_requested", json_object_new_boolean(owner_migration_requested));
    json_object_object_add(validations, "apply_supported", json_object_new_boolean(0));
    json_object_object_add(validations, "confirm_live_apply", json_object_new_boolean(0));
    json_object_object_add(validations, "reason", json_object_new_string("validate_and_dry_run_only_transaction_executor_pending"));

    json_object_object_add(root, "ok", json_object_new_boolean(1));
    json_object_object_add(root, "preview", json_object_new_boolean(1));
    json_object_object_add(root, "applied", json_object_new_boolean(0));
    json_object_object_add(root, "ifname", json_object_new_string(ifname));
    json_object_object_add(root, "current_port", json_object_get(port));
    json_object_object_add(root, "validations", validations);
    json_object_object_add(root, "preflight",
                           webd_port_network_transaction_preflight(ifname,
                               app_nc_json_str(body, "bridge", app_nc_json_str(body, "bridge_name", "br-lan")),
                               owner_id, target_owner_id));
    {
        struct json_object *dry_run =
            webd_port_network_transaction_dry_run(ifname,
                owner_migration_requested ? "port_reassignment_validate" : "vlan_runtime_validate",
                body, port, owner_id, target_owner_id);
        struct json_object *plan_for_preview = json_object_new_object();

        json_object_object_add(root, "dry_run", json_object_get(dry_run));
        json_object_object_add(plan_for_preview, "ifname", json_object_new_string(ifname));
        json_object_object_add(plan_for_preview, "current_owner_type", json_object_new_string(owner_type));
        json_object_object_add(plan_for_preview, "current_owner_id", json_object_new_string(owner_id));
        json_object_object_add(plan_for_preview, "target_owner_id", json_object_new_string(target_owner_id));
        json_object_object_add(plan_for_preview, "requires_confirm", json_object_new_boolean(1));
        json_object_object_add(plan_for_preview, "owner_migration_requested", json_object_new_boolean(owner_migration_requested));
        json_object_object_add(plan_for_preview, "vlan_profile_present", json_object_new_boolean(vlan_requested));
        json_object_object_add(plan_for_preview, "enabled_present", json_object_new_boolean(enabled_present));
        json_object_object_add(plan_for_preview, "target_enabled", json_object_new_boolean(enabled_value));
        if (owner_migration_requested) {
            struct json_object *mp = json_object_new_object();
            json_object_object_add(mp, "transaction_dry_run", json_object_get(dry_run));
            json_object_object_add(plan_for_preview, "migration_plan", mp);
        } else {
            struct json_object *vp = json_object_new_object();
            json_object_object_add(vp, "transaction_dry_run", json_object_get(dry_run));
            json_object_object_add(plan_for_preview, "vlan_runtime_plan", vp);
        }
        json_object_object_add(root, "transaction_preview",
                               webd_port_transaction_preview_from_plan(plan_for_preview, body, "web"));
        json_object_put(plan_for_preview);
        json_object_put(dry_run);
    }
    json_object_object_add(root, "capabilities", webd_topology_port_write_capabilities(port));
    json_object_object_add(root, "warnings", warnings);
    json_object_put(port);
    return webd_envelope(root, "webd.topology_port_transaction_validate");
}

struct json_object *webd_topology_node_ports_response(const struct http_req *req,
                                                             struct json_object *body,
                                                             int *http_status)
{
    char id[256] = "";
    char mac[64] = "";
    char port_id[256] = "";
    char ifname[128] = "";
    struct json_object *upstream = NULL;
    struct json_object *data = NULL;
    struct json_object *infra = NULL;
    struct json_object *ports = NULL;
    struct json_object *links = NULL;
    struct json_object *gateways = NULL;
    struct json_object *clients = NULL;
    struct json_object *discovery = NULL;
    struct json_object *items = json_object_new_array();
    struct json_object *root = json_object_new_object();
    struct json_object *cap = json_object_new_object();
    int matched = 0;
    int total = 0;
    int i;

    if (http_status)
        *http_status = 200;
    if (!webd_query_get(req ? req->query : "", "id", id, sizeof(id)))
        snprintf(id, sizeof(id), "%s", app_nc_json_str(body, "id", ""));
    if (!webd_query_get(req ? req->query : "", "mac", mac, sizeof(mac)))
        snprintf(mac, sizeof(mac), "%s", app_nc_json_str(body, "mac", ""));
    if (!webd_query_get(req ? req->query : "", "port_id", port_id, sizeof(port_id)))
        snprintf(port_id, sizeof(port_id), "%s", app_nc_json_str(body, "port_id", ""));
    if (!webd_query_get(req ? req->query : "", "ifname", ifname, sizeof(ifname)))
        snprintf(ifname, sizeof(ifname), "%s", app_nc_json_str(body, "ifname", ""));

    if ((id[0] && !webd_safe_token(id)) ||
        (mac[0] && !webd_safe_token(mac)) ||
        (port_id[0] && !webd_safe_token(port_id)) ||
        (ifname[0] && !webd_safe_token(ifname))) {
        if (items) json_object_put(items);
        if (root) json_object_put(root);
        if (cap) json_object_put(cap);
        if (http_status) *http_status = 400;
        return webd_error("invalid_topology_port_filter",
                          "topology port query contains invalid characters",
                          "id/mac/port_id/ifname", "webd.topology_ports");
    }

    upstream = webd_topology_infrastructure_cached_response(http_status);
    if (!upstream || !app_nc_json_bool(upstream, "ok", 0)) {
        if (items) json_object_put(items);
        if (root) json_object_put(root);
        if (cap) json_object_put(cap);
        if (upstream)
            return upstream;
        if (http_status) *http_status = 503;
        return webd_error("source_unavailable",
                          "topology infrastructure source is not available",
                          "dreamingwrt topology_infrastructure", "webd.topology_ports");
    }
    data = webd_data_or_self_from_jmx_response(upstream);
    if (!data) {
        if (items) json_object_put(items);
        if (root) json_object_put(root);
        if (cap) json_object_put(cap);
        if (upstream) json_object_put(upstream);
        if (http_status) *http_status = 503;
        return webd_error("source_unavailable",
                          "topology infrastructure source is not available",
                          "dreamingwrt topology_infrastructure", "webd.topology_ports");
    }
    infra = webd_obj_child_obj(data, "infrastructure");
    ports = webd_obj_child_array(infra, "ports");
    links = webd_obj_child_array(infra, "links");
    gateways = webd_obj_child_array(infra, "gateways");
    clients = webd_obj_child_array(infra, "clients");
    discovery = webd_obj_child_obj(infra, "discovery");

    if (ports && json_object_is_type(ports, json_type_array)) {
        total = json_object_array_length(ports);
        for (i = 0; i < total; i++) {
            struct json_object *p = json_object_array_get_idx(ports, i);
            struct json_object *o;
            struct json_object *g;
            struct json_object *related_links;
            struct json_object *cfg;
            const char *configured_display_name;
            const char *fallback_display_name;
            int configured_sort_order;

            if (!webd_port_matches_filter(p, id, mac, port_id, ifname))
                continue;
            matched++;
            o = json_object_get(p);
            g = webd_find_gateway_for_port(gateways, p);
            if (g)
                json_object_object_add(o, "device", json_object_get(g));
            /*
             * topology_infrastructure.ports[] already carries the persisted
             * physical_port_config record, including profile_id/profile entity
             * and last_apply status.  Do not overwrite it here; the port
             * drawer depends on this BFF preserving the exact backend contract.
             */
            if (!webd_obj_child_obj(o, "config"))
                json_object_object_add(o, "config", json_object_new_object());
            cfg = webd_obj_child_obj(o, "config");
            configured_display_name = app_nc_json_str(cfg, "display_name", "");
            fallback_display_name = app_nc_json_str(o, "name",
                app_nc_json_str(o, "ifname", ""));
            configured_sort_order = app_nc_json_int(cfg, "sort_order", 0);
            json_object_object_add(o, "display_name", json_object_new_string(
                configured_display_name[0] ? configured_display_name : fallback_display_name));
            json_object_object_add(o, "alias", json_object_new_string(configured_display_name));
            json_object_object_add(o, "sort_order", json_object_new_int(configured_sort_order));
            json_object_object_add(o, "configured_display_name",
                                   json_object_new_string(configured_display_name));
            json_object_object_add(o, "configured_sort_order",
                                   json_object_new_int(configured_sort_order));
            json_object_object_add(o, "display_metadata_source", json_object_new_string(
                configured_display_name[0] || configured_sort_order != 0 ?
                    "physical_port_config" : "ifname_fallback"));
            webd_add_port_related_links(o, links, p);
            related_links = webd_obj_child_array(o, "links");
            webd_add_port_neighbors(o, related_links, clients, discovery, p);
            webd_add_port_mac_contract(o, p);
            json_object_array_add(items, o);
        }
    }

    json_object_put(cap);
    cap = webd_topology_port_write_capabilities(items);

    json_object_object_add(root, "items", items);
    json_object_object_add(root, "ports", json_object_get(items));
    json_object_object_add(root, "total_ports", json_object_new_int(total));
    json_object_object_add(root, "matched_ports", json_object_new_int(matched));
    webd_obj_add_str(root, "id", id);
    webd_obj_add_str(root, "mac", mac);
    webd_obj_add_str(root, "port_id", port_id);
    webd_obj_add_str(root, "ifname", ifname);
    json_object_object_add(root, "capabilities", cap);
    json_object_object_add(root, "source", json_object_new_string("jmxd.topology_infrastructure"));
    json_object_object_add(root, "stale",
                           json_object_new_boolean(app_nc_json_bool(data, "stale", 0)));
    json_object_object_add(root, "degraded",
                           json_object_new_boolean(app_nc_json_bool(data, "degraded", 0)));
    if (app_nc_json_has(data, "cache_age_ms"))
        json_object_object_add(root, "cache_age_ms",
                               json_object_new_int(app_nc_json_int(data, "cache_age_ms", 0)));
    if (app_nc_json_str(data, "source_error", "")[0])
        json_object_object_add(root, "source_error",
                               json_object_new_string(app_nc_json_str(data, "source_error", "")));
    json_object_object_add(root, "diagnostics", json_object_new_object());
    json_object_object_add(webd_obj_child_obj(root, "diagnostics"), "complete", json_object_new_boolean(0));
    json_object_object_add(webd_obj_child_obj(root, "diagnostics"), "reason", json_object_new_string("port_manager_guarded_write_partial; neighbors_runtime_evidence_only"));
    if (discovery)
        json_object_object_add(webd_obj_child_obj(root, "diagnostics"), "discovery", json_object_get(discovery));

    if (data) json_object_put(data);
    if (upstream) json_object_put(upstream);
    return webd_envelope(root, "webd.topology_ports");
}

/* -- Port / VLAN manager response builders (Phase 7W) -----------------------
 * The port-manager capability probe, status aggregate, and the transaction
 * get/action/create/preview response builders, lifted verbatim out of
 * jmx_app_api.c. handle_client dispatches these; none is a jmx_api_route table
 * row, so no route moved. De-static'd; declared in api_ports_internal.h.
 * capabilities() is also reached by the transactions-query response builder
 * still in jmx_app_api.c, which resolves it via that header.
 */
struct json_object *webd_port_manager_capabilities(void)
{
    struct json_object *cap = json_object_new_object();

    json_object_object_add(cap, "read", json_object_new_boolean(1));
    json_object_object_add(cap, "status", json_object_new_boolean(1));
    json_object_object_add(cap, "transactions", json_object_new_boolean(1));
    json_object_object_add(cap, "transaction_list", json_object_new_boolean(1));
    json_object_object_add(cap, "transaction_get", json_object_new_boolean(1));
    json_object_object_add(cap, "transaction_create", json_object_new_boolean(1));
    json_object_object_add(cap, "transaction_preview", json_object_new_boolean(1));
    json_object_object_add(cap, "confirm", json_object_new_boolean(1));
    json_object_object_add(cap, "rollback", json_object_new_boolean(1));
    json_object_object_add(cap, "snapshot_rollback", json_object_new_boolean(1));
    json_object_object_add(cap, "apply_endpoint", json_object_new_string("/api/v1/topology/node/ports/apply"));
    json_object_object_add(cap, "preview_endpoint", json_object_new_string("/api/v1/topology/node/ports/preview"));
    json_object_object_add(cap, "status_endpoint", json_object_new_string("/api/v1/port-manager/status"));
    json_object_object_add(cap, "transactions_endpoint", json_object_new_string("/api/v1/port-manager/transactions"));
    json_object_object_add(cap, "transaction_create_endpoint", json_object_new_string("/api/v1/port-manager/transactions"));
    json_object_object_add(cap, "transaction_preview_endpoint", json_object_new_string("/api/v1/port-manager/transactions/preview"));
    json_object_object_add(cap, "confirm_endpoint", json_object_new_string("/api/v1/port-manager/transactions/{id}/confirm"));
    json_object_object_add(cap, "rollback_endpoint", json_object_new_string("/api/v1/port-manager/transactions/{id}/rollback"));
    json_object_object_add(cap, "executor_scope", json_object_new_string("config_apply_tasks"));
    json_object_object_add(cap, "confirm_live_apply", json_object_new_boolean(1));
    json_object_object_add(cap, "confirm_behavior", json_object_new_string("vlan_runtime_apply_pending_confirm_or_rollback"));
    json_object_object_add(cap, "live_apply_requires", json_object_new_string("DSA bridge VLAN/profile transaction with snapshot, reload, readback and health checks"));
    json_object_object_add(cap, "auto_rollback_worker", json_object_new_boolean(1));
    json_object_object_add(cap, "auto_rollback_worker_owner", json_object_new_string("dreamingwrt-init"));
    json_object_object_add(cap, "automatic_rollback", json_object_new_boolean(1));
    json_object_object_add(cap, "automatic_rollback_scope", json_object_new_string("/etc/config/network snapshot restore only"));
    json_object_object_add(cap, "network_mutation_executor", json_object_new_boolean(1));
    json_object_object_add(cap, "vlan_runtime_apply", json_object_new_boolean(1));
    json_object_object_add(cap, "poe_runtime_apply", json_object_new_boolean(0));
    json_object_object_add(cap, "port_migration_apply", json_object_new_boolean(0));
    json_object_object_add(cap, "reason",
                           json_object_new_string("DSA bridge VLAN/profile transactions can apply through guarded UCI reload with readback and rollback; PoE and WAN/LAN owner migration remain disabled"));
    return cap;
}

struct json_object *webd_port_manager_status_response(void)
{
    struct json_object *data = json_object_new_object();
    struct json_object *last = jmx_config_last_apply();
    struct json_object *pending = jmx_tasks_list_filtered(NULL, 1, 50);
    int pending_count = 0;
    int i, n;

    if (pending && json_object_is_type(pending, json_type_array)) {
        n = json_object_array_length(pending);
        for (i = 0; i < n; i++) {
            struct json_object *o = json_object_array_get_idx(pending, i);
            const char *state = app_nc_json_str(o, "state", "");

            if (!strcmp(state, "pending"))
                pending_count++;
        }
    }

    json_object_object_add(data, "state",
                           json_object_new_string(pending_count > 0 ? "pending" : "idle"));
    json_object_object_add(data, "pending_count", json_object_new_int(pending_count));
    json_object_object_add(data, "transactions", pending ? pending : json_object_new_array());
    json_object_object_add(data, "last_apply", last ? last : json_object_new_object());
    json_object_object_add(data, "capabilities", webd_port_manager_capabilities());
    json_object_object_add(data, "diagnostics", json_object_new_object());
    json_object_object_add(webd_obj_child_obj(data, "diagnostics"), "complete", json_object_new_boolean(1));
    json_object_object_add(webd_obj_child_obj(data, "diagnostics"), "reason",
                           json_object_new_string("DSA VLAN/profile guarded runtime transaction available; PoE and owner migration still disabled"));
    return webd_envelope(data, "webd.port_manager.status");
}

struct json_object *webd_port_manager_transaction_get_response(int task_id,
                                                                      int *http_status)
{
    struct json_object *task = jmx_tasks_get(task_id);
    const char *scope = app_nc_json_str(task, "scope", "");
    struct json_object *data = json_object_new_object();

    if (http_status)
        *http_status = 200;
    if (!app_nc_json_has(task, "id") || !jmx_task_is_port_scope(scope)) {
        if (http_status)
            *http_status = 404;
        if (task)
            json_object_put(task);
        json_object_put(data);
        return webd_error("transaction_not_found", "port-manager transaction was not found",
                          "task_id", "webd.port_manager.transactions");
    }
    json_object_object_add(data, "transaction", task);
    json_object_object_add(data, "capabilities", webd_port_manager_capabilities());
    return webd_envelope(data, "webd.port_manager.transaction");
}

struct json_object *webd_port_manager_transaction_action_response(int task_id,
                                                                         int rollback,
                                                                         struct json_object *body,
                                                                         int *http_status)
{
    struct json_object *task = jmx_tasks_get(task_id);
    const char *scope = app_nc_json_str(task, "scope", "");
    struct json_object *params = NULL;
    struct json_object *resp = NULL;

    if (http_status)
        *http_status = 200;
    if (!app_nc_json_has(task, "id") || !jmx_task_is_port_scope(scope)) {
        if (http_status)
            *http_status = 404;
        if (task)
            json_object_put(task);
        return webd_error("transaction_not_found", "port-manager transaction was not found",
                          "task_id", "webd.port_manager.transactions");
    }
    if (task)
        json_object_put(task);

    params = json_object_new_object();
    json_object_object_add(params, "task_id", json_object_new_int(task_id));
    if (body && json_object_is_type(body, json_type_object))
        webd_json_copy_key(params, "reason", body, "reason");
    resp = rollback ? jmx_config_rollback(params) : jmx_config_confirm(params);
    json_object_put(params);
    if (!resp) {
        if (http_status)
            *http_status = 500;
        return webd_error("transaction_action_failed", "port-manager transaction action failed",
                          rollback ? "rollback" : "confirm", "webd.port_manager.transactions");
    }
    if (!app_nc_json_bool(resp, "ok", 0) && http_status)
        *http_status = 409;
    json_object_object_add(resp, "capabilities", webd_port_manager_capabilities());
    return webd_envelope(resp, rollback ? "webd.port_manager.rollback" :
                         "webd.port_manager.confirm");
}

struct json_object *webd_port_manager_transaction_create_response(const struct http_req *req,
                                                                         struct json_object *body,
                                                                         const char *device_id,
                                                                         int *http_status)
{
    struct json_object *preview = NULL;
    struct json_object *preview_data = NULL;
    struct json_object *plan = NULL;
    struct json_object *changes = NULL;
    struct json_object *params = NULL;
    struct json_object *tx = NULL;
    struct json_object *data = json_object_new_object();
    const char *ifname = "";
    int rollback_timeout;
    int preview_status = 200;

    if (http_status)
        *http_status = 200;
    preview = webd_topology_port_plan_response(req, body, 0, device_id, &preview_status);
    preview_data = webd_obj_child_obj(preview, "data");
    plan = webd_obj_child_obj(preview_data, "plan");
    if (!preview || !preview_data || !plan) {
        if (preview)
            json_object_put(preview);
        json_object_put(data);
        if (http_status)
            *http_status = 500;
        return webd_error("port_plan_unavailable", "failed to build port transaction plan",
                          "plan", "webd.port_manager.transaction_create");
    }
    ifname = app_nc_json_str(plan, "ifname", "");
    changes = json_object_new_object();
    json_object_object_add(changes, "kind", json_object_new_string("port_manager_apply"));
    json_object_object_add(changes, "ifname", json_object_new_string(ifname));
    json_object_object_add(changes, "request", body ? json_object_get(body) : json_object_new_object());
    json_object_object_add(changes, "plan", json_object_get(plan));
    json_object_object_add(changes, "transaction_preview",
                           webd_port_transaction_preview_from_plan(plan, body, device_id));
    json_object_object_add(changes, "actor", json_object_new_string(device_id && device_id[0] ? device_id : "web"));
    json_object_object_add(changes, "created_by_endpoint",
                           json_object_new_string("/api/v1/port-manager/transactions"));

    rollback_timeout = app_nc_json_int(body, "rollback_timeout", 90);
    params = json_object_new_object();
    json_object_object_add(params, "scope", json_object_new_string("topology.port_manager"));
    json_object_object_add(params, "snapshot", json_object_new_boolean(1));
    json_object_object_add(params, "rollback_timeout", json_object_new_int(rollback_timeout));
    json_object_object_add(params, "changes", changes);
    tx = jmx_config_apply(params);
    json_object_put(params);

    if (!tx) {
        json_object_put(preview);
        json_object_put(data);
        if (http_status)
            *http_status = 500;
        return webd_error("transaction_create_failed", "failed to create port-manager transaction",
                          "config_apply_tasks", "webd.port_manager.transaction_create");
    }
    if (!app_nc_json_bool(tx, "ok", 0) && http_status)
        *http_status = 409;
    json_object_object_add(data, "transaction", tx);
    json_object_object_add(data, "transaction_preview",
                           webd_port_transaction_preview_from_plan(plan, body, device_id));
    json_object_object_add(data, "preview", preview);
    json_object_object_add(data, "capabilities", webd_port_manager_capabilities());
    json_object_object_add(data, "next_action", json_object_new_string("confirm_or_rollback"));
    json_object_object_add(data, "note",
                           json_object_new_string("transaction created; no live dataplane mutation has been applied yet"));
    return webd_envelope(data, "webd.port_manager.transaction_create");
}

struct json_object *webd_port_manager_transaction_preview_response(const struct http_req *req,
                                                                          struct json_object *body,
                                                                          const char *device_id,
                                                                          int *http_status)
{
    struct json_object *preview = NULL;
    struct json_object *preview_data = NULL;
    struct json_object *plan = NULL;
    struct json_object *data = json_object_new_object();
    struct json_object *tx_preview = NULL;
    int preview_status = 200;

    if (http_status)
        *http_status = 200;
    preview = webd_topology_port_plan_response(req, body, 0, device_id, &preview_status);
    preview_data = webd_obj_child_obj(preview, "data");
    plan = webd_obj_child_obj(preview_data, "plan");
    if (!preview || !preview_data || !plan) {
        if (preview)
            json_object_put(preview);
        json_object_put(data);
        if (http_status)
            *http_status = 500;
        return webd_error("port_plan_unavailable", "failed to build port transaction preview",
                          "plan", "webd.port_manager.transaction_preview");
    }
    tx_preview = webd_port_transaction_preview_from_plan(plan, body, device_id);
    json_object_object_add(data, "preview", preview);
    json_object_object_add(data, "transaction_preview", tx_preview);
    json_object_object_add(data, "capabilities", webd_port_manager_capabilities());
    json_object_object_add(data, "next_action", json_object_new_string("create_transaction_or_cancel"));
    json_object_object_add(data, "note",
                           json_object_new_string("dry-run only; no config transaction has been created and no live mutation has been applied"));
    return webd_envelope(data, "webd.port_manager.transaction_preview");
}

/* -- Port-manager transactions query (Phase 8C) ------------------------------
 * The transactions list/query response builder, lifted verbatim out of
 * jmx_app_api.c to sit beside the other port-manager builders (7W) and the
 * capability probe it embeds. handle_client dispatches it; declared in
 * api_ports_internal.h.
 */
struct json_object *webd_port_manager_transactions_query_response(const struct http_req *req,
                                                                  int *http_status)
{
    char scope[128] = "";
    char limit_s[32] = "";
    int limit = 50;
    struct json_object *data = json_object_new_object();
    struct json_object *items;

    if (http_status)
        *http_status = 200;
    if (req)
        webd_query_get(req->query, "scope", scope, sizeof(scope));
    if (scope[0] && !webd_safe_token(scope)) {
        if (http_status)
            *http_status = 400;
        json_object_put(data);
        return webd_error("invalid_scope", "scope contains invalid characters",
                          "scope", "webd.port_manager.transactions");
    }
    if (req && webd_query_get(req->query, "limit", limit_s, sizeof(limit_s)))
        app_parse_positive_int_segment(limit_s, &limit);
    items = jmx_tasks_list_filtered(scope, 1, limit);
    json_object_object_add(data, "items", items);
    json_object_object_add(data, "transactions", json_object_get(items));
    json_object_object_add(data, "total", json_object_new_int(json_object_array_length(items)));
    json_object_object_add(data, "scope", json_object_new_string(scope));
    json_object_object_add(data, "capabilities", webd_port_manager_capabilities());
    return webd_envelope(data, "webd.port_manager.transactions");
}
