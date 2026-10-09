// SPDX-License-Identifier: GPL-2.0-or-later
/* Platform half of the dedicated IPTV input transaction. No shell-built argv,
 * no UCI commit here: the shared journal publishes the prepared package bytes. */
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <ifaddrs.h>

static struct json_object *nc_iptv_ubus(const char *id, const char *method)
{
    const char *tool = access("/bin/ubus", X_OK) == 0 ? "/bin/ubus" : "/sbin/ubus";
    char object[128];
    snprintf(object, sizeof(object), "network.interface.%s", id);
    char *argv[] = {(char *)tool, "-S", "-t", "3", "call", object, (char *)method, NULL};
    struct jmx_exec_result result = {0};
    struct json_object *out = NULL;
    if (!jmx_exec_capture(tool, argv, 65536, 4000, &result) && !result.exit_code &&
        !result.term_signal && !result.timed_out && !result.truncated) {
        out = result.output && result.output_len ? json_tokener_parse(result.output) : json_object_new_object();
    }
    jmx_exec_result_free(&result);
    return out;
}

static int nc_iptv_carrier_enabled(const char *id)
{
    sqlite3_stmt *st=NULL; int yes=0;
    if (sqlite3_prepare_v2(g_netconfig_db,"SELECT 1 FROM wan w JOIN wan_advanced a ON a.wan_id=w.id WHERE w.id=?1 AND w.access_mode='pppoe' AND a.iptv_multicast_source='carrier'",-1,&st,NULL)==SQLITE_OK) {
        sqlite3_bind_text(st,1,id,-1,SQLITE_TRANSIENT); yes=sqlite3_step(st)==SQLITE_ROW;
    }
    sqlite3_finalize(st); return yes;
}

static struct json_object *nc_iptv_runtime(const char *id)
{
    struct json_object *out = nc_iptv_ubus(id, "status");
    if (!out) return json_tokener_parse("{\"available\":false,\"reason\":\"netifd_status_unavailable\"}");
    json_object_object_add(out, "available", json_object_new_boolean(1));
    if (nc_iptv_carrier_enabled(id)) {
        char carrier[32]; snprintf(carrier,sizeof(carrier),"%s_mc",id);
        json_object_object_add(out,"multicast_interface",json_object_new_string(carrier));
        json_object_object_add(out,"multicast",nc_iptv_ubus(carrier,"status"));
    }
    return out;
}

static int nc_iptv_reconnect(const char *id)
{
    struct json_object *out = nc_iptv_ubus(id, "down");
    if (!out) return -1;
    json_object_put(out);
    out = nc_iptv_ubus(id, "up");
    if (!out) return -1;
    json_object_put(out);
    if (nc_iptv_carrier_enabled(id)) {
        char carrier[32]; snprintf(carrier,sizeof(carrier),"%s_mc",id);
        out=nc_iptv_ubus(carrier,"down"); if(!out)return -1; json_object_put(out);
        out=nc_iptv_ubus(carrier,"up"); if(!out)return -1; json_object_put(out);
    }
    return 0;
}

static int nc_iptv_route_device(const char *address, char device[IFNAMSIZ])
{
    struct { struct nlmsghdr header; struct rtmsg route; char attributes[64]; } request = {0};
    unsigned char ip[16];
    int family = strchr(address, ':') ? AF_INET6 : AF_INET, bytes = family == AF_INET ? 4 : 16;
    if (inet_pton(family, address, ip) != 1) return -1;
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd < 0) return -1;
    struct timeval timeout = {1, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    request.header.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    request.header.nlmsg_type = RTM_GETROUTE;
    request.header.nlmsg_flags = NLM_F_REQUEST;
    request.header.nlmsg_seq = 1;
    request.route.rtm_family = family;
    request.route.rtm_dst_len = bytes * 8;
    struct rtattr *dst = (void *)((char *)&request + NLMSG_ALIGN(request.header.nlmsg_len));
    dst->rta_type = RTA_DST; dst->rta_len = RTA_LENGTH(bytes);
    memcpy(RTA_DATA(dst), ip, bytes);
    request.header.nlmsg_len = NLMSG_ALIGN(request.header.nlmsg_len) + RTA_LENGTH(bytes);
    struct sockaddr_nl kernel = {.nl_family = AF_NETLINK};
    int rc = -1;
    if (sendto(fd, &request, request.header.nlmsg_len, 0, (struct sockaddr *)&kernel, sizeof(kernel)) < 0) goto done;
    char response[8192];
    int length = (int)recv(fd, response, sizeof(response), 0);
    for (struct nlmsghdr *h = (void *)response; NLMSG_OK(h, length); h = NLMSG_NEXT(h, length)) {
        if (h->nlmsg_type != RTM_NEWROUTE || h->nlmsg_seq != 1) continue;
        struct rtmsg *r = NLMSG_DATA(h);
        int remaining = RTM_PAYLOAD(h);
        for (struct rtattr *a = RTM_RTA(r); RTA_OK(a, remaining); a = RTA_NEXT(a, remaining)) {
            if (a->rta_type != RTA_OIF || RTA_PAYLOAD(a) != sizeof(unsigned)) continue;
            unsigned index; memcpy(&index, RTA_DATA(a), sizeof(index));
            if (if_indextoname(index, device)) rc = 0;
        }
    }
done:
    close(fd);
    return rc;
}

static int nc_iptv_owned_section(struct uci_context *ctx, struct uci_section *s, const char *id)
{
    const char *owner = uci_lookup_option_string(ctx, s, "dreamingwrt_iptv_owner");
    return owner && !strcmp(owner, id);
}

static int nc_iptv_ref_token(const char *text, const char *id, const char *device)
{
    char copy[512];
    if (!text || strlen(text) >= sizeof(copy)) return text && *text;
    snprintf(copy, sizeof(copy), "%s", text);
    char *save = NULL;
    for (char *token = strtok_r(copy, " \t", &save); token; token = strtok_r(NULL, " \t", &save)) {
        if (*token == '@') token++;
        if (!strcmp(token, id) || (!strncmp(token,id,strlen(id))&&!strcmp(token+strlen(id),"_mc")) || nc_iptv_same_carrier(token, device)) return 1;
    }
    return 0;
}

static void nc_iptv_uci_check(struct uci_context *ctx, struct uci_package *pkg,
                               const char *id, const char *device, struct json_object *errors)
{
    const char *suffix[] = {"", "_dev", "_mc", "_mcast", "_zone", "_igmp", "_udp", "_dhcp", NULL};
    struct uci_element *element;
    uci_foreach_element(&pkg->sections, element) {
        struct uci_section *section = uci_to_section(element);
        int owns = nc_iptv_owned_section(ctx, section, id);
        for (int n = 0; suffix[n]; n++) {
            char reserved[40]; snprintf(reserved, sizeof(reserved), "%s%s", id, suffix[n]);
            if (!strcmp(section->e.name, reserved) && !owns)
                nc_add_field_error(errors, "id", "uci_resource_in_use", "Network section belongs to another owner");
        }
        if (owns) continue;
        struct uci_element *option;
        uci_foreach_element(&section->options, option) {
            struct uci_option *o = uci_to_option(option);
            const char *name = o->e.name;
            if (strcmp(name, "device") && strcmp(name, "ifname") && strcmp(name, "ports") &&
                strcmp(name, "network") && strcmp(name, "interface") &&
                (strcmp(pkg->e.name, "firewall") || (strcmp(name, "src") && strcmp(name, "dest")))) continue;
            int conflict = 0;
            if (o->type == UCI_TYPE_STRING) conflict = nc_iptv_ref_token(o->v.string, id, device);
            else if (o->type == UCI_TYPE_LIST) {
                struct uci_element *entry;
                uci_foreach_element(&o->v.list, entry)
                    if (nc_iptv_ref_token(entry->name, id, device)) conflict = 1;
            }
            if (conflict) nc_add_field_error(errors, "device", "uci_resource_in_use", "Another network section references this input or carrier");
        }
    }
}

static void nc_iptv_platform_check(struct json_object *config, struct json_object *request,
                                    struct json_object *errors)
{
    const char *device = nc_json_str(config, "device", ""), *id = nc_json_str(config, "id", "");
    int ignored = 0;
    struct json_object *old = nc_iptv_canonical(id, &ignored);
    const char *old_device_name = nc_json_str(old, "device", "");
    char route[IFNAMSIZ] = "", path[PATH_MAX];
    /* webd overwrites peer_ip from the actual accepted socket for both phases. */
    if (nc_iptv_route_device(nc_json_str(request, "peer_ip", ""), route))
        nc_add_field_error(errors, "device", "management_route_unavailable", "Cannot establish the management return route");
    else if (nc_iptv_same_carrier(route, device) || nc_iptv_same_carrier(route, old_device_name) || (!strncmp(route, "pppoe-", 6) && !strcmp(route + 6, id)))
        nc_add_field_error(errors, "device", "management_path_in_use", "Input carries the current management connection");
    if (!if_nametoindex(device) && strcmp(nc_json_str(request, "operation", ""), "delete"))
        nc_add_field_error(errors, "device", "carrier_missing", "Physical port is not present");
    snprintf(path, sizeof(path), "/sys/class/net/%s/master", device);
    if (!access(path, F_OK)) nc_add_field_error(errors, "device", "carrier_enslaved", "Physical port is a bridge or bond member");
    snprintf(path, sizeof(path), "/sys/class/net/%s", device);
    DIR *dir = opendir(path); struct dirent *entry;
    while (dir && (entry = readdir(dir))) {
        if (strncmp(entry->d_name, "upper_", 6)) continue;
        /* Existing owned VLAN may differ from the requested VLAN during edit. */
        char old_device[IFNAMSIZ];
        snprintf(old_device, sizeof(old_device), "%s.%s", old_device_name, nc_json_str(old, "vlan_id", ""));
        int own = old && nc_json_bool(old, "exists", 0) && nc_json_bool(old, "vlan_enabled", 0) && !strcmp(entry->d_name + 6, old_device);
        if (!own) nc_add_field_error(errors, "device", "carrier_in_use", "Physical port already has an upper device");
    }
    if (dir) closedir(dir);
    int changed_carrier = strcmp(old_device_name, device) != 0;
    if (old) json_object_put(old);
    if (!nc_json_bool(config, "exists", 0) || changed_carrier) {
        struct ifaddrs *addresses = NULL;
        if (!getifaddrs(&addresses)) {
            for (struct ifaddrs *a = addresses; a; a = a->ifa_next)
                if (a->ifa_addr && a->ifa_addr->sa_family == AF_INET && !strcmp(a->ifa_name, device))
                    nc_add_field_error(errors, "device", "carrier_has_address", "Physical port already has an IPv4 address");
            freeifaddrs(addresses);
        }
    }
    struct uci_context *ctx = uci_alloc_context(); struct uci_package *pkg = NULL;
    if (!ctx) { nc_add_field_error(errors, "device", "uci_unavailable", "Cannot read network configuration"); return; }
    uci_set_confdir(ctx, NC_TX_CONFIG_DIR);
    const char *packages[] = {"network", "firewall", NULL};
    for (int n = 0; packages[n]; n++) {
        pkg = NULL;
        if (uci_load(ctx, packages[n], &pkg) != UCI_OK)
            nc_add_field_error(errors, "device", "uci_unavailable", "Cannot read network configuration");
        else { nc_iptv_uci_check(ctx, pkg, id, device, errors); uci_unload(ctx, pkg); }
    }
    uci_free_context(ctx);
    struct json_object *status = nc_iptv_runtime(id), *routes = json_object_object_get(status, "route");
    for (size_t n = 0; routes && n < json_object_array_length(routes); n++) {
        struct json_object *r = json_object_array_get_idx(routes, n);
        if (!strcmp(nc_json_str(r, "target", ""), "0.0.0.0") && !nc_json_int(r, "mask", -1))
            nc_add_field_error(errors, "device", "input_has_default_route", "Input currently owns a default route");
    }
    if (status) json_object_put(status);
}

static int nc_iptv_prepare(struct json_object *config, const char *operation,
                           struct json_object *prepared)
{
    const char *id = nc_json_str(config, "id", ""), *device = nc_json_str(config, "device", "");
    const char *mode = nc_json_str(config, "access_mode", "dhcp");
    int removing = !strcmp(operation, "delete"), rc = -1;
    if (!strcmp(operation, "reconnect")) return 0;
    struct uci_context *ctx = uci_alloc_context();
    struct uci_package *network = NULL, *firewall = NULL;
    if (!ctx) return -1;
    uci_set_confdir(ctx, NC_TX_CONFIG_DIR);
    if (uci_load(ctx, "network", &network) != UCI_OK || uci_load(ctx, "firewall", &firewall) != UCI_OK) goto done;
    const char *suffix[] = {"", "_dev", "_mc", "_mcast", "_zone", "_igmp", "_udp", "_dhcp", NULL};
    for (int n = 0; suffix[n]; n++) {
        char section[40]; snprintf(section, sizeof(section), "%s%s", id, suffix[n]);
        if (nc_uci_delete_section_pkg(ctx, n < 4 ? "network" : "firewall", section)) goto done;
    }
    if (removing) {
        struct json_object *empty = safeops_network_rows(g_netconfig_db, "iptv", id);
        if (!empty) goto done;
        json_object_object_foreach(empty, key, value) { (void)value; json_object_object_add(empty, key, json_object_new_array()); }
        rc = safeops_network_restore_rows(g_netconfig_db, "iptv", id, empty);
        json_object_put(empty);
        if (rc) goto done;
    } else {
        if (jmx_netconfig_wan_set(config)) goto done;
        sqlite3_stmt *st=NULL;
        if (sqlite3_prepare_v2(g_netconfig_db,"INSERT INTO wan_advanced(wan_id,iptv_igmp_version,iptv_multicast_source,iptv_carrier_mode,iptv_carrier_address,iptv_carrier_prefix) VALUES(?1,?2,?3,?4,?5,?6) ON CONFLICT(wan_id) DO UPDATE SET iptv_igmp_version=excluded.iptv_igmp_version,iptv_multicast_source=excluded.iptv_multicast_source,iptv_carrier_mode=excluded.iptv_carrier_mode,iptv_carrier_address=excluded.iptv_carrier_address,iptv_carrier_prefix=excluded.iptv_carrier_prefix",-1,&st,NULL)!=SQLITE_OK) goto done;
        sqlite3_bind_text(st,1,id,-1,SQLITE_TRANSIENT);
        sqlite3_bind_int(st,2,nc_json_int(config,"igmp_version",0));
        sqlite3_bind_text(st,3,nc_json_str(config,"multicast_source","session"),-1,SQLITE_TRANSIENT);
        sqlite3_bind_text(st,4,nc_json_str(config,"carrier_access_mode","dhcp"),-1,SQLITE_TRANSIENT);
        sqlite3_bind_text(st,5,nc_json_str(config,"carrier_address",""),-1,SQLITE_TRANSIENT);
        sqlite3_bind_int(st,6,nc_json_int(config,"carrier_prefix",24));
        int saved=sqlite3_step(st)==SQLITE_DONE; sqlite3_finalize(st); if(!saved)goto done;
        int carrier=!strcmp(mode,"pppoe") && !strcmp(nc_json_str(config,"multicast_source","session"),"carrier");
        char actual_device[IFNAMSIZ], section[40], number[16];
        snprintf(actual_device, sizeof(actual_device), "%s", device);
#define IPTV_SECTION(package, object, name, type) do { \
    if (nc_uci_ensure_section(ctx, object, package, name, type) || \
        nc_uci_set_pkg(ctx, package, name, "dreamingwrt_iptv_owner", id)) goto done; \
} while (0)
#define IPTV_SET(package, name, key, value) do { if (nc_uci_set_pkg(ctx, package, name, key, value)) goto done; } while (0)
        if (nc_json_bool(config, "vlan_enabled", 0)) {
            snprintf(section, sizeof(section), "%s_dev", id);
            snprintf(actual_device, sizeof(actual_device), "%s.%s", device, nc_json_str(config, "vlan_id", ""));
            IPTV_SECTION("network", network, section, "device");
            IPTV_SET("network", section, "type", "8021q");
            IPTV_SET("network", section, "name", actual_device);
            IPTV_SET("network", section, "ifname", device);
            IPTV_SET("network", section, "vid", nc_json_str(config, "vlan_id", ""));
        }
        /* netifd owns per-device force_igmp_version across reload/reconnect. */
        int igmp=nc_json_int(config,"igmp_version",0);
        if (igmp) {
            char multicast_device[IFNAMSIZ];
            snprintf(multicast_device,sizeof(multicast_device),"%s",actual_device);
            if (!strcmp(mode,"pppoe") && !carrier) {
                snprintf(section,sizeof(section),"%s_mcast",id);
                snprintf(multicast_device,sizeof(multicast_device),"pppoe-%s",id);
            } else snprintf(section,sizeof(section),"%s_dev",id);
            IPTV_SECTION("network",network,section,"device");
            IPTV_SET("network",section,"name",multicast_device);
            snprintf(number,sizeof(number),"%d",igmp);
            IPTV_SET("network",section,"igmpversion",number);
        }
        char carrier_id[32]; snprintf(carrier_id,sizeof(carrier_id),"%s_mc",id);
        if (carrier) {
            const char *carrier_mode=nc_json_str(config,"carrier_access_mode","dhcp");
            IPTV_SECTION("network",network,carrier_id,"interface");
            IPTV_SET("network",carrier_id,"proto",carrier_mode);
            IPTV_SET("network",carrier_id,"device",actual_device);
            IPTV_SET("network",carrier_id,"defaultroute","0");
            IPTV_SET("network",carrier_id,"peerdns","0");
            IPTV_SET("network",carrier_id,"delegate","0");
            IPTV_SET("network",carrier_id,"ipv6","0");
            IPTV_SET("network",carrier_id,"metric","1000");
            IPTV_SET("network",carrier_id,"auto",nc_json_bool(config,"enabled",0)?"1":"0");
            IPTV_SET("network",carrier_id,"disabled",nc_json_bool(config,"enabled",0)?"0":"1");
            if (!strcmp(carrier_mode,"dhcp")) IPTV_SET("network",carrier_id,"vendorid",nc_json_str(config,"option60",""));
            else {
                char cidr[64];snprintf(cidr,sizeof(cidr),"%s/%d",nc_json_str(config,"carrier_address",""),nc_json_int(config,"carrier_prefix",24));
                IPTV_SET("network",carrier_id,"ipaddr",cidr);
            }
        }
        IPTV_SECTION("network", network, id, "interface");
        IPTV_SET("network", id, "proto", mode);
        IPTV_SET("network", id, "device", actual_device);
        IPTV_SET("network", id, "dreamingwrt_role", "iptv");
        IPTV_SET("network", id, "defaultroute", "0");
        IPTV_SET("network", id, "peerdns", "0");
        IPTV_SET("network", id, "delegate", "0");
        IPTV_SET("network", id, "ipv6", "0");
        IPTV_SET("network", id, "auto", nc_json_bool(config, "enabled", 0) ? "1" : "0");
        IPTV_SET("network", id, "disabled", nc_json_bool(config, "enabled", 0) ? "0" : "1");
        IPTV_SET("network", id, "metric", "1000");
        snprintf(number, sizeof(number), "%d", nc_json_int(config, "mtu", 1500));
        IPTV_SET("network", id, "mtu", number);
        if (!strcmp(mode, "dhcp")) IPTV_SET("network", id, "vendorid", nc_json_str(config, "option60", ""));
        if (!strcmp(mode, "pppoe")) {
            struct json_object *rows = safeops_network_rows(g_netconfig_db, "iptv", id);
            struct json_object *wan = rows ? json_object_array_get_idx(json_object_object_get(rows, "wan"), 0) : NULL;
            int ok = wan && !nc_uci_set_pkg(ctx, "network", id, "username", nc_json_str(wan, "username", "")) &&
                !nc_uci_set_pkg(ctx, "network", id, "password", nc_json_str(wan, "password_ref", ""));
            if (rows) json_object_put(rows);
            if (!ok) goto done;
        }
        if (!strcmp(mode, "static")) {
            struct json_object *address = json_object_array_get_idx(json_object_object_get(config, "addresses"), 0);
            char cidr[64]; snprintf(cidr, sizeof(cidr), "%s/%d", nc_json_str(address, "ip", ""), nc_json_int(address, "prefix", 0));
            IPTV_SET("network", id, "ipaddr", cidr);
            if (nc_json_str(config, "gateway", "")[0]) IPTV_SET("network", id, "gateway", nc_json_str(config, "gateway", ""));
        }
        snprintf(section, sizeof(section), "%s_zone", id);
        IPTV_SECTION("firewall", firewall, section, "zone");
        IPTV_SET("firewall", section, "name", id);
        char members[64]; snprintf(members,sizeof(members),"%s%s%s",id,carrier?" ":"",carrier?carrier_id:"");
        IPTV_SET("firewall", section, "network", members);
        IPTV_SET("firewall", section, "input", "REJECT");
        IPTV_SET("firewall", section, "output", "ACCEPT");
        IPTV_SET("firewall", section, "forward", "REJECT");
        for (int n = 0; n < 3; n++) {
            snprintf(section, sizeof(section), "%s_%s", id, n == 2 ? "dhcp" : n ? "udp" : "igmp");
            IPTV_SECTION("firewall", firewall, section, "rule");
            IPTV_SET("firewall", section, "src", id);
            IPTV_SET("firewall", section, "proto", n ? "udp" : "igmp");
            if (n == 2) {
                IPTV_SET("firewall", section, "src_port", "67");
                IPTV_SET("firewall", section, "dest_port", "68");
            } else IPTV_SET("firewall", section, "dest_ip", "224.0.0.0/4");
            IPTV_SET("firewall", section, "family", "ipv4");
            IPTV_SET("firewall", section, "target", "ACCEPT");
        }
#undef IPTV_SECTION
#undef IPTV_SET
    }
    rc = nc_tx_prepare_package(ctx, network, prepared);
    if (!rc) rc = nc_tx_prepare_package(ctx, firewall, prepared);
done:
    uci_free_context(ctx);
    return rc;
}
