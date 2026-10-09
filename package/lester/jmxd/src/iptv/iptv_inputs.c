// SPDX-License-Identifier: GPL-2.0-or-later
#define _GNU_SOURCE
/* References the existing network authority. This module never creates UCI,
 * changes routes, renews DHCP or assigns an address to a physical interface. */
#include "iptv.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern char **environ;

/* netifd owns the mapping from a configured WAN to its current L3 device.
 * In particular a VLAN or PPP session must not inherit the carrier's IP. */
static struct json_object *netifd_dump(void)
{
#if defined(IPTV_TESTING) && defined(IPTV_NETIFD_FIXTURE)
    return json_object_from_file(IPTV_NETIFD_FIXTURE);
#else
    const char *tool = access("/bin/ubus", X_OK) == 0 ? "/bin/ubus" : "/sbin/ubus";
    int fds[2];
    if (pipe2(fds, O_CLOEXEC)) return NULL;
    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_adddup2(&actions, fds[1], STDOUT_FILENO);
    posix_spawn_file_actions_addclose(&actions, fds[0]);
    posix_spawn_file_actions_addopen(&actions, STDIN_FILENO, "/dev/null", O_RDONLY, 0);
    posix_spawn_file_actions_addopen(&actions, STDERR_FILENO, "/dev/null", O_WRONLY, 0);
    char *argv[] = {(char *)tool, "-S", "-t", "1", "call", "network.interface", "dump", NULL};
    pid_t pid;
    int rc = posix_spawn(&pid, tool, &actions, NULL, argv, environ);
    posix_spawn_file_actions_destroy(&actions);
    close(fds[1]);
    if (rc) { close(fds[0]); return NULL; }
    char *text = malloc(128 * 1024);
    size_t used = 0;
    int finished = 0, status = 0;
    struct timespec start, now;
    clock_gettime(CLOCK_MONOTONIC, &start);
    while (text && used < 128 * 1024 - 1) {
        struct pollfd fd = {fds[0], POLLIN, 0};
        if (poll(&fd, 1, 100) > 0 && (fd.revents & (POLLIN | POLLHUP))) {
            ssize_t n = read(fds[0], text + used, 128 * 1024 - 1 - used);
            if (n == 0) { finished = 1; break; }
            if (n < 0) { if (errno == EINTR) continue; break; }
            used += (size_t)n;
        }
        clock_gettime(CLOCK_MONOTONIC, &now);
        if ((now.tv_sec - start.tv_sec) * 1000 + (now.tv_nsec - start.tv_nsec) / 1000000 >= 1500) break;
    }
    close(fds[0]);
    if (!finished) kill(pid, SIGKILL);
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
    struct json_object *result = NULL;
    if (text && finished && WIFEXITED(status) && !WEXITSTATUS(status)) {
        text[used] = 0;
        result = json_tokener_parse(text);
    }
    free(text);
    return result;
#endif
}

static struct json_object *netifd_interface(struct json_object *dump, const char *id)
{
    struct json_object *items = NULL;
    if (!dump || !json_object_object_get_ex(dump, "interface", &items) ||
        !json_object_is_type(items, json_type_array)) return NULL;
    for (size_t i = 0; i < json_object_array_length(items); i++) {
        struct json_object *item = json_object_array_get_idx(items, i);
        if (!strcmp(iptv_string(item, "interface"), id)) return item;
    }
    return NULL;
}

static int netifd_address(struct json_object *status, const char *address)
{
    struct json_object *addresses = NULL;
    if (!status || !json_object_object_get_ex(status, "ipv4-address", &addresses) ||
        !json_object_is_type(addresses, json_type_array)) return 0;
    for (size_t i = 0; i < json_object_array_length(addresses); i++)
        if (!strcmp(iptv_string(json_object_array_get_idx(addresses, i), "address"), address)) return 1;
    return 0;
}

static int netifd_default_route(struct json_object *status)
{
    struct json_object *routes = NULL;
    if (!status || !json_object_object_get_ex(status, "route", &routes) ||
        !json_object_is_type(routes, json_type_array)) return 0;
    for (size_t i = 0; i < json_object_array_length(routes); i++) {
        struct json_object *route = json_object_array_get_idx(routes, i);
        if (!strcmp(iptv_string(route, "target"), "0.0.0.0") &&
            iptv_integer(route, "mask", -1) == 0) return 1;
    }
    return 0;
}

static struct json_object *interface_groups(const char *device)
{
    FILE *f = fopen("/proc/net/igmp", "r");
    if (!f) return NULL;
    struct json_object *groups = json_object_new_array();
    char line[256], name[IFNAMSIZ];
    int selected = 0, index;
    while (fgets(line, sizeof(line), f)) {
        if (sscanf(line, "%d %15s :", &index, name) == 2 && line[0] != '\t') {
            selected = !strcmp(device, name);
            continue;
        }
        unsigned value;
        if (selected && sscanf(line, " %8x", &value) == 1) {
            struct in_addr address = {.s_addr = value};
            char text[INET_ADDRSTRLEN];
            if (inet_ntop(AF_INET, &address, text, sizeof(text)))
                json_object_array_add(groups, json_object_new_string(text));
        }
    }
    fclose(f);
    return groups;
}

static int default_route(const char *device)
{
    FILE *f = fopen("/proc/net/route", "r");
    if (!f) return 1;
    char line[512], name[IFNAMSIZ]; unsigned long destination; int found = 0;
    while (fgets(line, sizeof(line), f))
        if (sscanf(line, "%15s %lx", name, &destination) == 2 &&
            !destination && !strcmp(name, device)) found = 1;
    fclose(f); return found;
}

#ifndef IPTV_IGMP_SYSCTL_ROOT
#define IPTV_IGMP_SYSCTL_ROOT "/proc/sys/net/ipv4/conf"
#endif
static int input_igmp_version(const char *device)
{
    char path[512];int value=-1;
    if (!device[0] || strlen(device)>=IFNAMSIZ || strspn(device,"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-")!=strlen(device)) return -1;
    snprintf(path,sizeof(path),"%s/%s/force_igmp_version",IPTV_IGMP_SYSCTL_ROOT,device);
    FILE *f=fopen(path,"r");if(!f)return -1;
    if(fscanf(f,"%d",&value)!=1 || value<0 || value>3)value=-1;
    fclose(f);return value;
}

struct json_object *iptv_inputs(sqlite3 *db, struct iptv_error *e)
{
    sqlite3_stmt *stmt = NULL;
    const char *sql = "SELECT w.id,w.name,w.device,w.access_mode,w.enabled,"
        "COALESCE(a.default_route,1),w.vlan_id,COALESCE(a.dhcp_vendor_class,''),w.role,"
        "COALESCE(a.iptv_igmp_version,0),COALESCE(a.iptv_multicast_source,'session'),"
        "COALESCE(a.iptv_carrier_mode,'dhcp'),COALESCE(a.iptv_carrier_address,''),COALESCE(a.iptv_carrier_prefix,24) "
        "FROM wan w LEFT JOIN wan_advanced a ON a.wan_id=w.id ORDER BY w.name";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return iptv_fail(e, 503, "network_authority_unavailable", "");
    struct ifaddrs *addresses = NULL; getifaddrs(&addresses);
    struct json_object *dump = netifd_dump();
    struct json_object *result = json_object_new_object(), *items = json_object_new_array();
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        struct json_object *row = json_object_new_object();
        const char *keys[] = {"id", "name", "device", "access_mode", "enabled", "default_route", "vlan_id", "option60", "role", "igmp_version", "multicast_source", "carrier_access_mode", "carrier_address", "carrier_prefix"};
        for (int i = 0; i < 14; i++)
            json_object_object_add(row, keys[i], i == 4 || i == 5 ?
                json_object_new_boolean(sqlite3_column_int(stmt, i)) : (i == 9 || i == 13) ? json_object_new_int(sqlite3_column_int(stmt, i)) :
                json_object_new_string((const char *)sqlite3_column_text(stmt, i)));
        const char *mode = iptv_string(row, "access_mode");
        char interface_id[80];
        int carrier=!strcmp(mode,"pppoe")&&!strcmp(iptv_string(row,"multicast_source"),"carrier");
        snprintf(interface_id,sizeof(interface_id),"%s%s",iptv_string(row,"id"),carrier?"_mc":"");
        struct json_object *status = netifd_interface(dump, interface_id);
        json_object_object_add(row,"multicast_interface",json_object_new_string(interface_id));
        const char *device = status ? iptv_string(status, "l3_device") : "";
        int testing_direct = 0;
#ifdef IPTV_TESTING
        /* Existing loopback protocol fixtures have no netifd. This fallback is
         * deliberately absent from production. A supplied fixture never falls back. */
        if (!dump && !strcmp(iptv_string(row, "device"), "lo")) {
            device = "lo";
            testing_direct = 1;
        }
#endif
        char ip[INET_ADDRSTRLEN] = "";
        for (struct ifaddrs *a = addresses; a; a = a->ifa_next)
            if (a->ifa_addr && a->ifa_addr->sa_family == AF_INET &&
                !strcmp(a->ifa_name, device) && (a->ifa_flags & IFF_UP)) {
                char candidate[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &((struct sockaddr_in *)a->ifa_addr)->sin_addr, candidate, sizeof(candidate));
                if (testing_direct || netifd_address(status, candidate)) {
                    snprintf(ip, sizeof(ip), "%s", candidate);
                    break;
                }
            }
        int igmp_want=iptv_integer(row,"igmp_version",0),igmp_actual=input_igmp_version(device);
        const char *reason = !iptv_integer(row, "enabled", 0) ? "input_disabled" :
            (strcmp(mode, "dhcp") && strcmp(mode, "static") && strcmp(mode, "pppoe")) ? "input_access_mode_not_supported" :
            (!status && !testing_direct) ? "network_runtime_unavailable" :
            (!testing_direct && !iptv_integer(status, "up", 0)) ? "input_link_down" :
            iptv_integer(row, "default_route", 1) || netifd_default_route(status) || default_route(device) ? "input_is_default_route" :
            !*ip ? "input_address_unavailable" :
            igmp_want && igmp_actual<0 ? "igmp_runtime_unavailable" :
            igmp_want && igmp_actual!=igmp_want ? "igmp_version_pending" : "";
        json_object_object_add(row,"igmp_version_effective",igmp_actual<0?NULL:json_object_new_int(igmp_actual));
        json_object_object_add(row, "runtime_device", json_object_new_string(device));
        json_object_object_add(row, "runtime_source", json_object_new_string(testing_direct ? "test_loopback" : "netifd"));
        json_object_object_add(row, "local_address", json_object_new_string(ip));
        json_object_object_add(row, "available", json_object_new_boolean(!*reason));
        json_object_object_add(row, "reason", *reason ? json_object_new_string(reason) : NULL);
        /* A configured interface/address is not evidence of multicast traffic. */
        json_object_object_add(row, "group_joined", NULL);
        json_object_object_add(row, "media_received", NULL);
        json_object_object_add(row, "interface_groups", *device ? interface_groups(device) : NULL);
        json_object_array_add(items, row);
    }
    if (addresses) freeifaddrs(addresses);
    if (dump) json_object_put(dump);
    sqlite3_finalize(stmt); json_object_object_add(result, "items", items);
    /* The separately versioned core owns mutation support. Consumers must
     * probe its snapshot contract instead of inferring support from iptvd. */
    json_object_object_add(result, "network_mutation_supported", NULL);
    json_object_object_add(result, "network_mutation_authority", json_object_new_string("config.snapshot:iptv"));
    return result;
}

int iptv_source_url(sqlite3 *db, struct json_object *channel, char *out,
                    size_t size, int runtime, struct iptv_error *e)
{
    const char *url = iptv_string(channel, "source_url");
    int multicast = !strncmp(url, "udp://", 6) || !strncmp(url, "rtp://", 6);
    int known = multicast || !strncmp(url, "http://", 7) || !strncmp(url, "https://", 8) ||
        !strncmp(url, "rtsp://", 7) || !strncmp(url, "rtmp://", 7);
    if (!known || strlen(url) > 2048 || strpbrk(url, "\r\n\t ")) {
        iptv_fail(e, 400, "input_protocol_unsupported", "source_url"); return -1;
    }
    if (strchr(url, '@') || strchr(url, '?')) {
        iptv_fail(e, 422, "source_credentials_not_supported", "source_url"); return -1;
    }
    if (!multicast || !strcmp(iptv_string(channel, "mode"), "external")) {
        if(runtime)return iptv_access_resolve(db,channel,out,size,e);
        if (snprintf(out, size, "%s", url) >= (int)size) return -1;
        return 0;
    }
    char host[64], extra; unsigned port; struct in_addr group;
    if (sscanf(url + 6, "%63[^:]:%u%c", host, &port, &extra) != 2 || !port || port > 65535 ||
        inet_pton(AF_INET, host, &group) != 1 || !IN_MULTICAST(ntohl(group.s_addr))) {
        iptv_fail(e, 400, "multicast_address_required", "source_url"); return -1;
    }
    const char *id = iptv_string(channel, "input_id");
    struct json_object *catalog = iptv_inputs(db, e), *items = NULL, *input = NULL;
    if (!catalog) return -1;
    json_object_object_get_ex(catalog, "items", &items);
    for (size_t i = 0; i < json_object_array_length(items); i++) {
        struct json_object *item = json_object_array_get_idx(items, i);
        if (!strcmp(iptv_string(item, "id"), id)) {input = item; break;}
    }
    int result = -1;
    if (!input) iptv_fail(e, 409, "input_binding_required", "input_id");
    else if (runtime && !iptv_integer(input, "available", 0))
        iptv_fail(e, 409, iptv_string(input, "reason"), "input_id");
    else if (snprintf(out, size, "%s?localaddr=%s&reuse=1", url,
                       iptv_string(input, "local_address")) < (int)size) result = 0;
    json_object_put(catalog); return result;
}
