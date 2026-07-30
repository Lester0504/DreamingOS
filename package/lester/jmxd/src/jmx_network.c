// SPDX-License-Identifier: GPL-2.0-or-later
/* 
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>  
*/
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <ctype.h>
#include <limits.h>
#include <ifaddrs.h>
#include <net/if.h>
#ifndef JMX_NETWORK_DEFENSIVE_ONLY
#include <libubox/uloop.h>
#include <libubox/utils.h>
#include <libubus.h>
#endif
#include <time.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <json-c/json.h>
#ifndef JMX_NETWORK_DEFENSIVE_ONLY
#include <uci.h>
#include "jmx.h"
#include "jmx_user.h"
#include "jmx_netlink.h"
#include "jmx_ubus.h"
#include "jmx_config.h"
#include "jmx_utils.h"
#include "jmx_uci.h"
#include "jmx_netconfig_db.h"
#endif
#include "jmx_network.h"
#define MAX_INET_ADDR_LEN 32
#define MAX_MAC_ADDR_LEN 18

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

#ifndef JMX_IFSTATUS_PATH
#define JMX_IFSTATUS_PATH "/sbin/ifstatus"
#endif

#define JMX_IFSTATUS_MAX_OUTPUT (256U * 1024U)

int jmx_interface_name_valid(const char *ifname, int require_existing)
{
    size_t i, len;

    if (!ifname || !(len = strlen(ifname)) || len >= IFNAMSIZ)
        return 0;
    for (i = 0; i < len; i++) {
        unsigned char ch = (unsigned char)ifname[i];

        if (!isalnum(ch) && ch != '_' && ch != '-' && ch != '.' && ch != ':')
            return 0;
    }
    return !require_existing || if_nametoindex(ifname) != 0;
}

static int jmx_canonical_address(int family, const char *value,
                                 char *output, size_t output_len)
{
    unsigned char address[sizeof(struct in6_addr)];
    char canonical[INET6_ADDRSTRLEN];

    if (!value || !value[0] || !output || output_len == 0 ||
        inet_pton(family, value, address) != 1 ||
        !inet_ntop(family, address, canonical, sizeof(canonical)) ||
        strlen(canonical) >= output_len)
        return -1;
    memcpy(output, canonical, strlen(canonical) + 1);
    return 0;
}

static int jmx_json_ipv4_string(struct json_object *obj,
                                char *output, size_t output_len)
{
    if (!obj || !json_object_is_type(obj, json_type_string))
        return -1;
    if (jmx_canonical_address(AF_INET, json_object_get_string(obj),
                              output, output_len) != 0)
        return -1;
    return strcmp(output, json_object_get_string(obj)) == 0 ? 0 : -1;
}

static int jmx_prefix_to_mask(int prefix, char *output, size_t output_len)
{
    struct in_addr address;

    if (prefix < 0 || prefix > 32 || !output || output_len < INET_ADDRSTRLEN)
        return -1;
    address.s_addr = htonl(prefix == 0 ? 0U : 0xffffffffU << (32 - prefix));
    return inet_ntop(AF_INET, &address, output, output_len) ? 0 : -1;
}

int jmx_iface_status_parse_json(const char *json, iface_status_t *status)
{
    iface_status_t parsed;
    struct json_object *root = NULL;
    struct json_tokener *tokener = NULL;
    struct json_object *array = NULL;
    struct json_object *entry = NULL;
    struct json_object *value = NULL;
    size_t json_len, parse_end;
    int i;

    if (!json || !status)
        return -1;
    json_len = strlen(json);
    if (json_len > INT_MAX)
        return -1;
    memset(&parsed, 0, sizeof(parsed));
    tokener = json_tokener_new();
    if (!tokener)
        return -1;
    root = json_tokener_parse_ex(tokener, json, (int)json_len);
    if (!root || json_tokener_get_error(tokener) != json_tokener_success ||
        !json_object_is_type(root, json_type_object))
        goto fail;
    parse_end = json_tokener_get_parse_end(tokener);
    while (parse_end < json_len && isspace((unsigned char)json[parse_end]))
        parse_end++;
    if (parse_end != json_len)
        goto fail;
    json_tokener_free(tokener);
    tokener = NULL;

    if (json_object_object_get_ex(root, "ipv4-address", &array)) {
        if (!json_object_is_type(array, json_type_array))
            goto fail;
        if (json_object_array_length(array) > 0) {
            entry = json_object_array_get_idx(array, 0);
            if (!entry || !json_object_is_type(entry, json_type_object) ||
                !json_object_object_get_ex(entry, "address", &value) ||
                jmx_json_ipv4_string(value, parsed.ip, sizeof(parsed.ip)) != 0 ||
                !json_object_object_get_ex(entry, "mask", &value) ||
                !json_object_is_type(value, json_type_int) ||
                jmx_prefix_to_mask(json_object_get_int(value), parsed.mask,
                                   sizeof(parsed.mask)) != 0)
                goto fail;
        }
    }

    array = NULL;
    if (json_object_object_get_ex(root, "route", &array)) {
        if (!json_object_is_type(array, json_type_array))
            goto fail;
        if (json_object_array_length(array) > 0) {
            entry = json_object_array_get_idx(array, 0);
            if (!entry || !json_object_is_type(entry, json_type_object))
                goto fail;
            if (json_object_object_get_ex(entry, "nexthop", &value) &&
                jmx_json_ipv4_string(value, parsed.gateway,
                                     sizeof(parsed.gateway)) != 0)
                goto fail;
        }
    }

    array = NULL;
    if (json_object_object_get_ex(root, "dns-server", &array)) {
        size_t count;

        if (!json_object_is_type(array, json_type_array))
            goto fail;
        count = json_object_array_length(array);
        if (count > 0 &&
            jmx_json_ipv4_string(json_object_array_get_idx(array, 0),
                                 parsed.dns1, sizeof(parsed.dns1)) != 0)
            goto fail;
        if (count > 1 &&
            jmx_json_ipv4_string(json_object_array_get_idx(array, 1),
                                 parsed.dns2, sizeof(parsed.dns2)) != 0)
            goto fail;
    }

    array = NULL;
    if (json_object_object_get_ex(root, "ipv6-address", &array)) {
        if (!json_object_is_type(array, json_type_array))
            goto fail;
        for (i = 0; i < (int)json_object_array_length(array); i++) {
            char candidate[sizeof(parsed.ipv6)];

            entry = json_object_array_get_idx(array, i);
            if (!entry || !json_object_is_type(entry, json_type_object) ||
                !json_object_object_get_ex(entry, "address", &value) ||
                !json_object_is_type(value, json_type_string) ||
                jmx_canonical_address(AF_INET6, json_object_get_string(value),
                                      candidate, sizeof(candidate)) != 0)
                goto fail;
            if (strncmp(candidate, "fe80:", 5) != 0 && !parsed.ipv6[0])
                memcpy(parsed.ipv6, candidate, strlen(candidate) + 1);
        }
    }

    *status = parsed;
    json_object_put(root);
    return 0;

fail:
    if (tokener)
        json_tokener_free(tokener);
    if (root)
        json_object_put(root);
    return -1;
}

char *get_interface_status_buf(char *ifname)
{
    char *const argv[] = { (char *)JMX_IFSTATUS_PATH, ifname, NULL };
    char *buffer = NULL;
    size_t capacity = 4096, used = 0;
    int descriptors[2] = { -1, -1 };
    int status = 0;
    pid_t child;

    if (!jmx_interface_name_valid(ifname, 0) || pipe(descriptors) != 0)
        return NULL;
    child = fork();
    if (child < 0) {
        close(descriptors[0]);
        close(descriptors[1]);
        return NULL;
    }
    if (child == 0) {
        int null_fd;

        close(descriptors[0]);
        if (dup2(descriptors[1], STDOUT_FILENO) < 0)
            _exit(126);
        close(descriptors[1]);
        null_fd = open("/dev/null", O_WRONLY | O_CLOEXEC);
        if (null_fd >= 0) {
            (void)dup2(null_fd, STDERR_FILENO);
            close(null_fd);
        }
        execv(JMX_IFSTATUS_PATH, argv);
        _exit(127);
    }
    close(descriptors[1]);
    descriptors[1] = -1;
    buffer = malloc(capacity);
    if (!buffer)
        goto fail;
    for (;;) {
        ssize_t count;

        if (used == capacity - 1) {
            size_t next_capacity;
            char *next;

            if (capacity >= JMX_IFSTATUS_MAX_OUTPUT + 1U)
                goto fail;
            next_capacity = capacity * 2U;
            if (next_capacity > JMX_IFSTATUS_MAX_OUTPUT + 1U)
                next_capacity = JMX_IFSTATUS_MAX_OUTPUT + 1U;
            next = realloc(buffer, next_capacity);
            if (!next)
                goto fail;
            buffer = next;
            capacity = next_capacity;
        }
        count = read(descriptors[0], buffer + used, capacity - used - 1U);
        if (count < 0 && errno == EINTR)
            continue;
        if (count < 0)
            goto fail;
        if (count == 0)
            break;
        used += (size_t)count;
    }
    close(descriptors[0]);
    descriptors[0] = -1;
    while (waitpid(child, &status, 0) < 0) {
        if (errno != EINTR)
            goto fail_no_child;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
        goto fail_no_child;
    buffer[used] = '\0';
    return buffer;

fail:
    if (descriptors[0] >= 0)
        close(descriptors[0]);
    kill(child, SIGKILL);
    while (waitpid(child, NULL, 0) < 0 && errno == EINTR)
        ;
fail_no_child:
    free(buffer);
    return NULL;
}

#ifndef JMX_NETWORK_DEFENSIVE_ONLY
#include "jmx_exec.h"

#define JMX_SERVICE_ACTION_TIMEOUT_MS 30000

static int jmx_network_service_action(const char *service, const char *action)
{
    const char *path;
    struct jmx_exec_result result;
    char *argv[3];
    int ok;

    if (!service || !action ||
        (strcmp(action, "reload") != 0 && strcmp(action, "restart") != 0))
        return -1;
    if (strcmp(service, "network") == 0)
        path = "/etc/init.d/network";
    else if (strcmp(service, "dnsmasq") == 0)
        path = "/etc/init.d/dnsmasq";
    else
        return -1;

    argv[0] = (char *)path;
    argv[1] = (char *)action;
    argv[2] = NULL;
    if (jmx_exec_wait(path, argv, JMX_SERVICE_ACTION_TIMEOUT_MS, &result) != 0)
        return -1;
    ok = !result.timed_out && result.term_signal == 0 && result.exit_code == 0;
    jmx_exec_result_free(&result);
    return ok ? 0 : -1;
}

static int jmx_ipv6_prefix_length(const struct sockaddr_in6 *mask)
{
    const unsigned char *bytes;
    int prefix = 0;
    int i;

    if (!mask)
        return -1;
    bytes = (const unsigned char *)&mask->sin6_addr;
    for (i = 0; i < 16; i++) {
        unsigned char byte = bytes[i];
        int bit;

        for (bit = 7; bit >= 0; bit--) {
            if (byte & (1U << bit))
                prefix++;
            else
                return prefix;
        }
    }
    return prefix;
}

static int jmx_ipv6_is_gua(const struct in6_addr *addr)
{
    const unsigned char *bytes = (const unsigned char *)addr;

    return addr && (bytes[0] & 0xe0U) == 0x20U;
}

static void jmx_ipv6_add_unique(jmx_iface_ipv6_contract_t *contract,
                                const char *cidr)
{
    int i;

    if (!contract || !cidr || !cidr[0])
        return;
    for (i = 0; i < contract->address_count; i++) {
        if (!strcasecmp(contract->addresses[i], cidr))
            return;
    }
    if (contract->address_count >= JMX_IPV6_CONTRACT_ADDR_MAX)
        return;
    snprintf(contract->addresses[contract->address_count],
             sizeof(contract->addresses[contract->address_count]), "%s", cidr);
    contract->address_count++;
}

static int jmx_ipv6_hex_addr(const char *hex, struct in6_addr *addr)
{
    int i;

    if (!hex || strlen(hex) != 32 || !addr)
        return -1;
    for (i = 0; i < 16; i++) {
        unsigned int byte;

        if (sscanf(hex + i * 2, "%2x", &byte) != 1)
            return -1;
        addr->s6_addr[i] = (unsigned char)byte;
    }
    return 0;
}

static void jmx_ipv6_collect_delegated_prefix(const char *ifname,
                                              jmx_iface_ipv6_contract_t *contract)
{
    FILE *fp;
    char line[512];
    int best_prefix = 129;

    fp = fopen("/proc/net/ipv6_route", "r");
    if (!fp)
        return;
    while (fgets(line, sizeof(line), fp)) {
        char dest[33], source[33], next_hop[33], dev[IFNAMSIZ];
        unsigned int dest_prefix, source_prefix;
        unsigned int metric, refcnt, use, flags;
        struct in6_addr source_addr;
        char address[INET6_ADDRSTRLEN];

        if (sscanf(line, "%32s %2x %32s %2x %32s %8x %8x %8x %8x %15s",
                   dest, &dest_prefix, source, &source_prefix, next_hop,
                   &metric, &refcnt, &use, &flags, dev) != 10)
            continue;
        if (strcmp(dev, ifname) || dest_prefix != 0 || source_prefix == 0 ||
            source_prefix >= (unsigned int)best_prefix ||
            strspn(dest, "0") != 32 || jmx_ipv6_hex_addr(source, &source_addr) != 0 ||
            !jmx_ipv6_is_gua(&source_addr) ||
            !inet_ntop(AF_INET6, &source_addr, address, sizeof(address)))
            continue;
        best_prefix = (int)source_prefix;
        snprintf(contract->delegated_prefix,
                 sizeof(contract->delegated_prefix), "%s/%u",
                 address, source_prefix);
    }
    fclose(fp);
}

int jmx_iface_ipv6_contract_collect(const char *ifname,
                                    jmx_iface_ipv6_contract_t *contract)
{
    struct ifaddrs *ifaddr = NULL, *ifa;

    if (!contract)
        return -1;
    memset(contract, 0, sizeof(*contract));
    if (!ifname || !ifname[0] || strlen(ifname) >= IFNAMSIZ ||
        if_nametoindex(ifname) == 0 || getifaddrs(&ifaddr) != 0)
        return -1;
    for (ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
        const struct sockaddr_in6 *sin6;
        const struct sockaddr_in6 *mask6;
        char address[INET6_ADDRSTRLEN];
        char cidr[JMX_IPV6_CONTRACT_TEXT_MAX];
        int prefix;

        if (!ifa->ifa_addr || !ifa->ifa_name || strcmp(ifa->ifa_name, ifname) ||
            ifa->ifa_addr->sa_family != AF_INET6)
            continue;
        sin6 = (const struct sockaddr_in6 *)ifa->ifa_addr;
        if (IN6_IS_ADDR_UNSPECIFIED(&sin6->sin6_addr) ||
            IN6_IS_ADDR_LOOPBACK(&sin6->sin6_addr) ||
            IN6_IS_ADDR_MULTICAST(&sin6->sin6_addr) ||
            !inet_ntop(AF_INET6, &sin6->sin6_addr, address, sizeof(address)))
            continue;
        mask6 = (const struct sockaddr_in6 *)ifa->ifa_netmask;
        prefix = jmx_ipv6_prefix_length(mask6);
        if (prefix >= 0)
            snprintf(cidr, sizeof(cidr), "%s/%d", address, prefix);
        else
            snprintf(cidr, sizeof(cidr), "%s", address);
        jmx_ipv6_add_unique(contract, cidr);
        if (!contract->link_local[0] && IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr))
            snprintf(contract->link_local, sizeof(contract->link_local), "%s", cidr);
        else if (!contract->global[0] && jmx_ipv6_is_gua(&sin6->sin6_addr))
            snprintf(contract->global, sizeof(contract->global), "%s", cidr);
    }
    freeifaddrs(ifaddr);
    jmx_ipv6_collect_delegated_prefix(ifname, contract);
    return contract->address_count > 0 ? 0 : -1;
}

void jmx_iface_ipv6_contract_add_json(struct json_object *obj,
                                      const char *ifname)
{
    jmx_iface_ipv6_contract_t contract;
    struct json_object *addresses = json_object_new_array();
    struct json_object *existing = NULL;
    const char *source;
    int i;

    if (!obj || !addresses)
        return;
    jmx_iface_ipv6_contract_collect(ifname, &contract);
    for (i = 0; i < contract.address_count; i++)
        json_object_array_add(addresses,
                              json_object_new_string(contract.addresses[i]));
    source = contract.global[0] ? "runtime_device_addr" :
             (contract.link_local[0] ? "runtime_device_link_local_only" :
                                       "runtime_device_addr_unavailable");
    json_object_object_add(obj, "ipv6", json_object_new_string(contract.global));
    json_object_object_add(obj, "ipv6_addr", json_object_new_string(contract.global));
    json_object_object_add(obj, "ipv6_global", json_object_new_string(contract.global));
    json_object_object_add(obj, "global_ipv6", json_object_new_string(contract.global));
    json_object_object_add(obj, "public_ipv6", json_object_new_string(contract.global));
    json_object_object_add(obj, "ipv6_link_local",
                           json_object_new_string(contract.link_local));
    json_object_object_add(obj, "link_local_ipv6",
                           json_object_new_string(contract.link_local));
    json_object_object_add(obj, "ipv6_addrs", addresses);
    if (contract.delegated_prefix[0] ||
        !json_object_object_get_ex(obj, "delegated_prefix", &existing))
        json_object_object_add(obj, "delegated_prefix",
                               json_object_new_string(contract.delegated_prefix));
    json_object_object_add(obj, "ipv6_source", json_object_new_string(source));
}

int get_iface_status(char *ifname, iface_status_t *status){
    char *buf = NULL;

    if (!status || !(buf = get_interface_status_buf(ifname))) {
        LOG_ERROR("get interface status buf error\n");
        return -1;
    }
    if (jmx_iface_status_parse_json(buf, status) != 0) {
        LOG_ERROR("get_iface_status: invalid netifd JSON contract\n");
        free(buf);
        return -1;
    }
    free(buf);
    return 0;
}


char *cidr2str(int cidr) {
    if (cidr < 0 || cidr > 32) {
        return NULL;
    }
    
    static char mask_str[16];
    unsigned int mask = cidr == 0 ? 0U : 0xFFFFFFFFU << (32 - cidr);
    

    snprintf(mask_str, sizeof(mask_str), "%d.%d.%d.%d",
        (mask >> 24) & 0xFF,
        (mask >> 16) & 0xFF,
        (mask >> 8) & 0xFF,
        mask & 0xFF);
    
    return mask_str;
}


static int interface_name_matches(const char *ifname, const char *prefix) {
    size_t len;

    if (!ifname || !prefix) return 0;
    len = strlen(prefix);
    if (strlen(ifname) < len) return 0;
    return strncasecmp(ifname, prefix, len) == 0;
}


static void append_lan_dhcp_to_response(struct json_object *data_obj);
static int update_lan_dhcp_from_req(struct json_object *dhcp_obj);


static const char *get_section_option_value(struct uci_section *s, const char *option_name) {
    if (!s || !option_name) return NULL;
    
    struct uci_option *o = uci_lookup_option(s->package->ctx, s, option_name);
    if (!o || o->type != UCI_TYPE_STRING) {
        return NULL;
    }
    return o->v.string;
}


static void get_section_list_values(struct uci_section *s, const char *option_name, 
                                     struct json_object *array) {
    if (!s || !option_name || !array) return;
    
    struct uci_option *o = uci_lookup_option(s->package->ctx, s, option_name);
    if (!o || o->type != UCI_TYPE_LIST) {
        return;
    }
    
    struct uci_element *e;
    uci_foreach_element(&o->v.list, e) {
        json_object_array_add(array, json_object_new_string(e->name));
    }
}


static struct json_object *get_interface_list_by_type(const char *iftype) {
    struct json_object *data_obj = json_object_new_object();
    struct json_object *interfaces_array = json_object_new_array();
    LOG_DEBUG("get_interface_list_by_type called\n");
    struct uci_context *ctx = uci_alloc_context();
    if (!ctx) {
        LOG_ERROR("Failed to allocate UCI context\n");
        json_object_put(data_obj);
        return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    struct uci_package *pkg = NULL;
    if (uci_load(ctx, "network", &pkg) != UCI_OK) {
        LOG_ERROR("Failed to load network package\n");
        uci_free_context(ctx);
        json_object_put(data_obj);
        return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    

    struct uci_element *e;
    uci_foreach_element(&pkg->sections, e) {
		
        struct uci_section *s = uci_to_section(e);
		
		LOG_DEBUG("s = %p\n", s);
        LOG_DEBUG("s->type: %s\n", s->type);

        if (strcmp(s->type, "interface") != 0) {
            continue;
        }

        const char *name_str = s->e.name;
		
        if (!name_str) {
            continue;
        }
        LOG_DEBUG("name_str: %s\n", name_str);

        
        if (!interface_name_matches(name_str, iftype)) {
			LOG_DEBUG("not match \n");
            continue;
        }
        
        const char *device_str = get_section_option_value(s, "device");
        const char *proto_str = get_section_option_value(s, "proto");
        const char *ipaddr_str = get_section_option_value(s, "ipaddr");
        const char *netmask_str = get_section_option_value(s, "netmask");
        const char *gateway_str = get_section_option_value(s, "gateway");
        
        LOG_DEBUG("get_interface_list_by_type: device=%s, proto=%s, ipaddr=%s\n", 
                 device_str ? device_str : "NULL",
                 proto_str ? proto_str : "NULL",
                 ipaddr_str ? ipaddr_str : "NULL");
        

        struct json_object *dns_array = json_object_new_array();
        if (!dns_array) {
            LOG_ERROR("get_interface_list_by_type: Failed to create dns_array\n");
            continue;
        }
        get_section_list_values(s, "dns", dns_array);
        
        LOG_DEBUG("get_interface_list_by_type: Creating interface object\n");
        struct json_object *iface_obj = json_object_new_object();
        if (!iface_obj) {
            LOG_ERROR("get_interface_list_by_type: Failed to create iface_obj\n");
            json_object_put(dns_array);
            continue;
        }
        
        json_object_object_add(iface_obj, "name", json_object_new_string(name_str));
        json_object_object_add(iface_obj, "device", json_object_new_string(device_str ? device_str : ""));
        json_object_object_add(iface_obj, "proto", json_object_new_string(proto_str ? proto_str : ""));
        json_object_object_add(iface_obj, "ipaddr", json_object_new_string(ipaddr_str ? ipaddr_str : ""));
        json_object_object_add(iface_obj, "netmask", json_object_new_string(netmask_str ? netmask_str : ""));
        json_object_object_add(iface_obj, "gateway", json_object_new_string(gateway_str ? gateway_str : ""));
        json_object_object_add(iface_obj, "dns", dns_array);
        
        LOG_DEBUG("get_interface_list_by_type: Added interface %s to array\n", name_str);
        json_object_array_add(interfaces_array, iface_obj);
        LOG_DEBUG("222222222222\n");
    }
    
	LOG_DEBUG("22222222\n");
	
	
    uci_free_context(ctx);
    
	
    json_object_object_add(data_obj, "list", interfaces_array);
    LOG_DEBUG("data_obj: %s\n", json_object_to_json_string(data_obj));
    return jmx_gen_api_response_data(API_CODE_SUCCESS, data_obj);
}


struct json_object *jmx_api_get_lan_list(struct json_object *req_obj) {
    (void)req_obj;
    LOG_DEBUG("jmx_api_get_lan_list: called\n");
    struct json_object *result = get_interface_list_by_type("lan");
    LOG_DEBUG("jmx_api_get_lan_list: returning result\n");
    return result;
}


struct json_object *jmx_api_get_wan_list(struct json_object *req_obj) {
    (void)req_obj;
    LOG_DEBUG("jmx_api_get_wan_list: called\n");
    struct json_object *result = get_interface_list_by_type("wan");
    LOG_DEBUG("jmx_api_get_wan_list: returning result\n");
    return result;
}


static struct json_object *add_or_mod_interface(struct json_object *req_obj, const char *iftype, int is_add) {
	int i;
	if (!req_obj) {
        return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    struct json_object *name_obj = json_object_object_get(req_obj, "name");
    struct json_object *device_obj = json_object_object_get(req_obj, "device");
    struct json_object *proto_obj = json_object_object_get(req_obj, "proto");
    
    if (!name_obj || !device_obj || !proto_obj) {
        LOG_ERROR("Missing required fields: name, device, proto\n");
        return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    const char *name = json_object_get_string(name_obj);
    const char *device = json_object_get_string(device_obj);
    const char *proto = json_object_get_string(proto_obj);
    

    if (!interface_name_matches(name, iftype)) {
        LOG_ERROR("Interface name '%s' must start with '%s'\n", name, iftype);
        return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    

    if (strcmp(proto, "dhcp") != 0 && strcmp(proto, "static") != 0 && 
        (strcmp(iftype, "wan") != 0 || strcmp(proto, "pppoe") != 0)) {
        LOG_ERROR("Invalid protocol '%s' for %s interface\n", proto, iftype);
        return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    

    if (strcmp(proto, "static") == 0) {
        struct json_object *ipaddr_obj = json_object_object_get(req_obj, "ipaddr");
        struct json_object *netmask_obj = json_object_object_get(req_obj, "netmask");
        if (!ipaddr_obj || !netmask_obj) {
            LOG_ERROR("ipaddr and netmask are required for static protocol\n");
            return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
        }
    }
    
    struct uci_context *ctx = uci_alloc_context();
    if (!ctx) {
        LOG_ERROR("Failed to allocate UCI context\n");
        return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    

    struct uci_ptr ptr;
    char uci_path[256];
    snprintf(uci_path, sizeof(uci_path), "network.%s", name);
    
    int exists = (uci_lookup_ptr(ctx, &ptr, uci_path, true) == UCI_OK);
    
    if (is_add) {

        if (exists) {
            LOG_ERROR("Interface '%s' already exists\n", name);
            uci_free_context(ctx);
            return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
        }
    } else {

        if (!exists) {
            LOG_ERROR("Interface '%s' not found\n", name);
            uci_free_context(ctx);
            return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
        }
    }
    

    if (is_add) {


        char section_path[256];
        snprintf(section_path, sizeof(section_path), "network.%s=interface", name);
        
        struct uci_ptr ptr;
        if (uci_lookup_ptr(ctx, &ptr, section_path, true) != UCI_OK) {
            LOG_ERROR("Failed to create interface section '%s'\n", name);
            uci_free_context(ctx);
            return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
        }
        
        if (uci_set(ctx, &ptr) != UCI_OK) {
            LOG_ERROR("Failed to set interface section '%s'\n", name);
            uci_free_context(ctx);
            return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
        }
        
        if (uci_save(ctx, ptr.p) != UCI_OK) {
            LOG_ERROR("Failed to save network package\n");
            if (ptr.p) uci_unload(ctx, ptr.p);
            uci_free_context(ctx);
            return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
        }
        
        if (ptr.p) uci_unload(ctx, ptr.p);
    }
    

    snprintf(uci_path, sizeof(uci_path), "network.%s.device", name);
    jmx_uci_set_value(ctx, uci_path, (char *)device);
    

    snprintf(uci_path, sizeof(uci_path), "network.%s.proto", name);
    jmx_uci_set_value(ctx, uci_path, (char *)proto);
    

    if (strcmp(proto, "static") == 0) {
        struct json_object *ipaddr_obj = json_object_object_get(req_obj, "ipaddr");
        struct json_object *netmask_obj = json_object_object_get(req_obj, "netmask");
        struct json_object *gateway_obj = json_object_object_get(req_obj, "gateway");
        
        if (ipaddr_obj) {
            snprintf(uci_path, sizeof(uci_path), "network.%s.ipaddr", name);
            jmx_uci_set_value(ctx, uci_path, (char *)json_object_get_string(ipaddr_obj));
        }
        
        if (netmask_obj) {
            snprintf(uci_path, sizeof(uci_path), "network.%s.netmask", name);
            jmx_uci_set_value(ctx, uci_path, (char *)json_object_get_string(netmask_obj));
        }
        
        if (gateway_obj) {
            snprintf(uci_path, sizeof(uci_path), "network.%s.gateway", name);
            jmx_uci_set_value(ctx, uci_path, (char *)json_object_get_string(gateway_obj));
        }
        

        struct json_object *dns_obj = json_object_object_get(req_obj, "dns");
        if (dns_obj && json_object_is_type(dns_obj, json_type_array)) {

            char dns_path[256];
            snprintf(dns_path, sizeof(dns_path), "network.%s.dns", name);
            jmx_uci_delete(ctx, dns_path);
            

            struct uci_ptr ptr;
            memset(&ptr, 0, sizeof(ptr));
            ptr.package = "network";
            ptr.section = name;
            ptr.option = "dns";
            
            int dns_len = json_object_array_length(dns_obj);
            for (i = 0; i < dns_len; i++) {
                struct json_object *dns_item = json_object_array_get_idx(dns_obj, i);
                const char *dns_str = json_object_get_string(dns_item);
                if (dns_str && strlen(dns_str) > 0) {
                    ptr.value = (char *)dns_str;
                    if (uci_add_list(ctx, &ptr) != UCI_OK) {
                        LOG_ERROR("Failed to add DNS to list: %s\n", dns_str);
                    }
                }
            }
        }
    } else if (strcmp(proto, "pppoe") == 0 && strcmp(iftype, "wan") == 0) {

        struct json_object *username_obj = json_object_object_get(req_obj, "username");
        struct json_object *password_obj = json_object_object_get(req_obj, "password");
        
        if (username_obj) {
            snprintf(uci_path, sizeof(uci_path), "network.%s.username", name);
            jmx_uci_set_value(ctx, uci_path, (char *)json_object_get_string(username_obj));
        }
        
        if (password_obj) {
            snprintf(uci_path, sizeof(uci_path), "network.%s.password", name);
            jmx_uci_set_value(ctx, uci_path, (char *)json_object_get_string(password_obj));
        }
    }
    
    jmx_uci_commit(ctx, "network");
    uci_free_context(ctx);
    
    LOG_DEBUG("%s interface '%s' %s successfully\n", iftype, name, is_add ? "added" : "modified");
    return jmx_gen_api_response_data(API_CODE_SUCCESS, NULL);
}


struct json_object *jmx_api_add_lan(struct json_object *req_obj) {
    LOG_DEBUG("jmx_api_add_lan called\n");
    return add_or_mod_interface(req_obj, "lan", 1);
}


struct json_object *jmx_api_mod_lan(struct json_object *req_obj) {
    LOG_DEBUG("jmx_api_mod_lan called\n");
    return add_or_mod_interface(req_obj, "lan", 0);
}


struct json_object *jmx_api_add_wan(struct json_object *req_obj) {
    LOG_DEBUG("jmx_api_add_wan called\n");
    return add_or_mod_interface(req_obj, "wan", 1);
}


struct json_object *jmx_api_mod_wan(struct json_object *req_obj) {
    LOG_DEBUG("jmx_api_mod_wan called\n");
    return add_or_mod_interface(req_obj, "wan", 0);
}


static struct json_object *del_interface(struct json_object *req_obj, const char *iftype) {
    if (!req_obj) {
        return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    struct json_object *name_obj = json_object_object_get(req_obj, "name");
    if (!name_obj) {
        LOG_ERROR("Missing required field: name\n");
        return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    const char *name = json_object_get_string(name_obj);
    

    if (!interface_name_matches(name, iftype)) {
        LOG_ERROR("Interface name '%s' must start with '%s'\n", name, iftype);
        return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    struct uci_context *ctx = uci_alloc_context();
    if (!ctx) {
        LOG_ERROR("Failed to allocate UCI context\n");
        return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    

    struct uci_ptr ptr;
    char uci_path[256];
    snprintf(uci_path, sizeof(uci_path), "network.%s", name);
    
    if (uci_lookup_ptr(ctx, &ptr, uci_path, true) != UCI_OK) {
        LOG_ERROR("Interface '%s' not found\n", name);
        uci_free_context(ctx);
        return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    

    jmx_uci_delete(ctx, uci_path);
    
    jmx_uci_commit(ctx, "network");
    uci_free_context(ctx);
    
    LOG_DEBUG("%s interface '%s' deleted successfully\n", iftype, name);
    return jmx_gen_api_response_data(API_CODE_SUCCESS, NULL);
}


struct json_object *jmx_api_del_lan(struct json_object *req_obj) {
    LOG_DEBUG("jmx_api_del_lan called\n");
    return del_interface(req_obj, "lan");
}


struct json_object *jmx_api_del_wan(struct json_object *req_obj) {
    LOG_DEBUG("jmx_api_del_wan called\n");
    return del_interface(req_obj, "wan");
}


struct json_object *jmx_api_get_lan_info(struct json_object *req_obj) {
    (void)req_obj;
    LOG_DEBUG("jmx_api_get_lan_info called\n");
    
    struct json_object *data_obj = json_object_new_object();
    if (!data_obj) {
        return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    struct uci_context *ctx = uci_alloc_context();
    if (!ctx) {
        LOG_ERROR("Failed to allocate UCI context\n");
        json_object_put(data_obj);
        return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    char ipaddr_str[32] = {0};
    char netmask_str[32] = {0};
    char proto_str[32] = {0};
    char gateway_str[32] = {0};
    char dns1_str[32] = {0};
    char dns2_str[32] = {0};
    
    jmx_uci_get_value(ctx, "network.lan.ipaddr", ipaddr_str, sizeof(ipaddr_str));
    jmx_uci_get_value(ctx, "network.lan.netmask", netmask_str, sizeof(netmask_str));
    jmx_uci_get_value(ctx, "network.lan.proto", proto_str, sizeof(proto_str));
    jmx_uci_get_value(ctx, "network.lan.gateway", gateway_str, sizeof(gateway_str));
    

    char dns_list_buf[128] = {0};
    if (jmx_uci_get_list_value(ctx, "network.lan.dns", dns_list_buf, sizeof(dns_list_buf), " ") == 0) {
        char *saveptr = NULL;
        char *p = strtok_r(dns_list_buf, " ", &saveptr);
        if (p) {
            strncpy(dns1_str, p, sizeof(dns1_str) - 1);
            p = strtok_r(NULL, " ", &saveptr);
            if (p) {
                strncpy(dns2_str, p, sizeof(dns2_str) - 1);
            }
        }
    }
    
    json_object_object_add(data_obj, "ipaddr", json_object_new_string(ipaddr_str));
    json_object_object_add(data_obj, "netmask", json_object_new_string(netmask_str));
    json_object_object_add(data_obj, "proto", json_object_new_string(proto_str));
    json_object_object_add(data_obj, "gateway", json_object_new_string(gateway_str));
    json_object_object_add(data_obj, "dns1", json_object_new_string(dns1_str));
    json_object_object_add(data_obj, "dns2", json_object_new_string(dns2_str));
    append_lan_dhcp_to_response(data_obj);
    
    uci_free_context(ctx);
    
    return jmx_gen_api_response_data(API_CODE_SUCCESS, data_obj);
}


struct json_object *jmx_api_set_lan_info(struct json_object *req_obj) {
    LOG_DEBUG("jmx_api_set_lan_info called22\n");
    
    if (!req_obj) {
        return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    
    struct uci_context *ctx = uci_alloc_context();
    if (!ctx) {
        LOG_ERROR("Failed to allocate UCI context\n");
        return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    

    char test_buf[32] = {0};
    if (jmx_uci_get_value(ctx, "network.lan.proto", test_buf, sizeof(test_buf)) != 0) {

        if (jmx_uci_set_value(ctx, "network.lan", "interface") != 0) {
            LOG_ERROR("Failed to create lan section\n");
            uci_free_context(ctx);
            return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
        }
    }
    
    

    struct json_object *ipaddr_obj = json_object_object_get(req_obj, "ipaddr");
    struct json_object *netmask_obj = json_object_object_get(req_obj, "netmask");
    struct json_object *proto_obj = json_object_object_get(req_obj, "proto");
    struct json_object *gateway_obj = json_object_object_get(req_obj, "gateway");
    struct json_object *dns1_obj = json_object_object_get(req_obj, "dns1");
    struct json_object *dns2_obj = json_object_object_get(req_obj, "dns2");
    
    if (proto_obj) {
        const char *proto = json_object_get_string(proto_obj);
        if (proto && strcmp(proto, "pppoe") == 0) {
            LOG_ERROR("LAN interface does not support PPPoE protocol\n");
            uci_free_context(ctx);
            return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
        }
        jmx_uci_set_value(ctx, "network.lan.proto", (char *)proto);
    }
    
    
    if (ipaddr_obj) {
        jmx_uci_set_value(ctx, "network.lan.ipaddr", (char *)json_object_get_string(ipaddr_obj));
    }
    
    if (netmask_obj) {
        jmx_uci_set_value(ctx, "network.lan.netmask", (char *)json_object_get_string(netmask_obj));
    }
    
    if (gateway_obj) {
        jmx_uci_set_value(ctx, "network.lan.gateway", (char *)json_object_get_string(gateway_obj));
    }
    

    if (dns1_obj || dns2_obj) {
        jmx_uci_delete(ctx, "network.lan.dns");
        
        struct uci_ptr ptr;
        memset(&ptr, 0, sizeof(ptr));
        ptr.package = "network";
        ptr.section = "lan";
        ptr.option = "dns";
        
        if (dns1_obj) {
            const char *dns1 = json_object_get_string(dns1_obj);
            if (dns1 && strlen(dns1) > 0) {
                ptr.value = (char *)dns1;
                if (uci_add_list(ctx, &ptr) != UCI_OK) {
                    LOG_ERROR("Failed to add DNS1 to list\n");
                }
            }
        }
        
        if (dns2_obj) {
            const char *dns2 = json_object_get_string(dns2_obj);
            if (dns2 && strlen(dns2) > 0) {
                ptr.value = (char *)dns2;
                if (uci_add_list(ctx, &ptr) != UCI_OK) {
                    LOG_ERROR("Failed to add DNS2 to list\n");
                }
            }
        }
    }
    jmx_uci_commit(ctx, "network");
    uci_free_context(ctx);
    update_lan_dhcp_from_req(json_object_object_get(req_obj, "dhcp"));
    if (jmx_network_service_action("network", "restart") != 0 ||
        jmx_network_service_action("dnsmasq", "restart") != 0) {
        LOG_ERROR("Failed to restart LAN runtime services\n");
        return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    return jmx_gen_api_response_data(API_CODE_SUCCESS, NULL);
}


struct json_object *jmx_api_get_wan_info(struct json_object *req_obj) {
    (void)req_obj;
    LOG_DEBUG("jmx_api_get_wan_info called\n");
    
    struct json_object *data_obj = json_object_new_object();
    if (!data_obj) {
        return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    struct uci_context *ctx = uci_alloc_context();
    if (!ctx) {
        LOG_ERROR("Failed to allocate UCI context\n");
        json_object_put(data_obj);
        return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    char ipaddr_str[32] = {0};
    char netmask_str[32] = {0};
    char proto_str[32] = {0};
    char gateway_str[32] = {0};
    char dns1_str[32] = {0};
    char dns2_str[32] = {0};
    char username_str[128] = {0};
    char password_str[128] = {0};
    
    jmx_uci_get_value(ctx, "network.wan.ipaddr", ipaddr_str, sizeof(ipaddr_str));
    jmx_uci_get_value(ctx, "network.wan.netmask", netmask_str, sizeof(netmask_str));
    jmx_uci_get_value(ctx, "network.wan.proto", proto_str, sizeof(proto_str));
    jmx_uci_get_value(ctx, "network.wan.gateway", gateway_str, sizeof(gateway_str));
    jmx_uci_get_value(ctx, "network.wan.username", username_str, sizeof(username_str));
    jmx_uci_get_value(ctx, "network.wan.password", password_str, sizeof(password_str));
    

    char dns_list_buf[128] = {0};
    if (jmx_uci_get_list_value(ctx, "network.wan.dns", dns_list_buf, sizeof(dns_list_buf), " ") == 0) {
        char *saveptr = NULL;
        char *p = strtok_r(dns_list_buf, " ", &saveptr);
        if (p) {
            strncpy(dns1_str, p, sizeof(dns1_str) - 1);
            p = strtok_r(NULL, " ", &saveptr);
            if (p) {
                strncpy(dns2_str, p, sizeof(dns2_str) - 1);
            }
        }
    }
    
    json_object_object_add(data_obj, "ipaddr", json_object_new_string(ipaddr_str));
    json_object_object_add(data_obj, "netmask", json_object_new_string(netmask_str));
    json_object_object_add(data_obj, "proto", json_object_new_string(proto_str));
    json_object_object_add(data_obj, "gateway", json_object_new_string(gateway_str));
    json_object_object_add(data_obj, "dns1", json_object_new_string(dns1_str));
    json_object_object_add(data_obj, "dns2", json_object_new_string(dns2_str));
    json_object_object_add(data_obj, "username", json_object_new_string(username_str));
    json_object_object_add(data_obj, "password", json_object_new_string(password_str));
    
    uci_free_context(ctx);
    
    return jmx_gen_api_response_data(API_CODE_SUCCESS, data_obj);
}


struct json_object *jmx_api_set_wan_info(struct json_object *req_obj) {
    LOG_DEBUG("jmx_api_set_wan_info called\n");
    
    if (!req_obj) {
        return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    struct uci_context *ctx = uci_alloc_context();
    if (!ctx) {
        LOG_ERROR("Failed to allocate UCI context\n");
        return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    

    char test_buf[32] = {0};
    if (jmx_uci_get_value(ctx, "network.wan.proto", test_buf, sizeof(test_buf)) != 0) {

        if (jmx_uci_set_value(ctx, "network.wan", "interface") != 0) {
            LOG_ERROR("Failed to create wan section\n");
            uci_free_context(ctx);
            return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
        }
    }
    

    struct json_object *proto_obj = json_object_object_get(req_obj, "proto");
    const char *proto = NULL;
    if (proto_obj) {
        proto = json_object_get_string(proto_obj);
        jmx_uci_set_value(ctx, "network.wan.proto", (char *)proto);
    } else {

        char proto_buf[32] = {0};
        if (jmx_uci_get_value(ctx, "network.wan.proto", proto_buf, sizeof(proto_buf)) == 0) {
            proto = proto_buf;
        }
    }
    
    if (!proto) {
        LOG_ERROR("Protocol not specified and cannot be determined\n");
        uci_free_context(ctx);
        return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    LOG_DEBUG("proto: %s\n", proto);

    if (strcmp(proto, "static") == 0) {

        struct json_object *ipaddr_obj = json_object_object_get(req_obj, "ipaddr");
        struct json_object *netmask_obj = json_object_object_get(req_obj, "netmask");
        struct json_object *gateway_obj = json_object_object_get(req_obj, "gateway");
        struct json_object *dns1_obj = json_object_object_get(req_obj, "dns1");
        struct json_object *dns2_obj = json_object_object_get(req_obj, "dns2");
        
        if (ipaddr_obj) {
            jmx_uci_set_value(ctx, "network.wan.ipaddr", (char *)json_object_get_string(ipaddr_obj));
        }
        
        if (netmask_obj) {
            jmx_uci_set_value(ctx, "network.wan.netmask", (char *)json_object_get_string(netmask_obj));
        }
        
        if (gateway_obj) {
            jmx_uci_set_value(ctx, "network.wan.gateway", (char *)json_object_get_string(gateway_obj));
        }

        if (dns1_obj || dns2_obj) {
            jmx_uci_delete(ctx, "network.wan.dns");
            
            struct uci_ptr ptr;
            memset(&ptr, 0, sizeof(ptr));
            ptr.package = "network";
            ptr.section = "wan";
            ptr.option = "dns";
            
            if (dns1_obj) {
                const char *dns1 = json_object_get_string(dns1_obj);
                if (dns1 && strlen(dns1) > 0) {
                    ptr.value = (char *)dns1;
                    
                    if (uci_add_list(ctx, &ptr) != UCI_OK) {
                        LOG_ERROR("Failed to add DNS1 to list\n");
                    }
                }
            }
            
            if (dns2_obj) {
                
                const char *dns2 = json_object_get_string(dns2_obj);
                if (dns2 && strlen(dns2) > 0) {
                    
                    ptr.value = (char *)dns2;
                    if (uci_add_list(ctx, &ptr) != UCI_OK) {
                        LOG_ERROR("Failed to add DNS2 to list\n");
                    }
                }
            }
            
        }
    } else if (strcmp(proto, "pppoe") == 0) {
        struct json_object *username_obj = json_object_object_get(req_obj, "username");
        struct json_object *password_obj = json_object_object_get(req_obj, "password");
        if (username_obj) {
            const char *username = json_object_get_string(username_obj);
            if (username && strlen(username) > 0) {
                
                jmx_uci_set_value(ctx, "network.wan.username", (char *)username);
            }
        }
    
        if (password_obj) {
            const char *password = json_object_get_string(password_obj);
            if (password && strlen(password) > 0) {
                
                jmx_uci_set_value(ctx, "network.wan.password", (char *)password);
            }
        }
         
    } else if (strcmp(proto, "dhcp") == 0) {
        
    }
    
    jmx_uci_commit(ctx, "network");
    uci_free_context(ctx);
    

    LOG_DEBUG("Reloading network configuration...\n");
    if (jmx_network_service_action("network", "reload") != 0) {
        LOG_ERROR("Failed to reload network\n");
        return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    LOG_DEBUG("WAN interface info updated successfully\n");
    return jmx_gen_api_response_data(API_CODE_SUCCESS, NULL);
}


struct json_object *jmx_api_get_work_mode(struct json_object *req_obj)
{
    (void)req_obj;
    LOG_DEBUG("jmx_api_get_work_mode called\n");
    int work_mode = 0;
    if (jmx_work_mode_config_get(&work_mode, NULL, 0, NULL, 0) != 0) {
        LOG_ERROR("jmx_api_get_work_mode: config.db read failed\n");
        return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    struct json_object *data_obj = json_object_new_object();
    if (!data_obj)
        return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
    json_object_object_add(data_obj, "work_mode", json_object_new_int(work_mode));
    json_object_object_add(data_obj, "source", json_object_new_string("config.db:work_mode_settings"));
    return jmx_gen_api_response_data(API_CODE_SUCCESS, data_obj);
}


struct json_object *jmx_api_set_work_mode(struct json_object *req_obj)
{
    LOG_DEBUG("jmx_api_set_work_mode called\n");
    if (!req_obj) {
        return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    struct json_object *wm_obj = json_object_object_get(req_obj, "work_mode");
    if (!wm_obj) {
        LOG_ERROR("jmx_api_set_work_mode: missing work_mode\n");
        return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    int work_mode = json_object_get_int(wm_obj);
    if (work_mode != 0 && work_mode != 1) {
        LOG_ERROR("jmx_api_set_work_mode: invalid work_mode %d\n", work_mode);
        return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
    }

    if (jmx_work_mode_config_set_legacy(work_mode) != 0) {
        LOG_ERROR("jmx_api_set_work_mode: config.db update failed\n");
        return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
    }

	update_jmx_proc_u32_value("work_mode", work_mode);

    LOG_DEBUG("jmx_api_set_work_mode: work_mode=%d\n", work_mode);
    return jmx_gen_api_response_data(API_CODE_SUCCESS, NULL);
}


static int parse_leasetime_to_minutes(const char *lt)
{
    if (!lt || lt[0] == '\0') return 0;
    int len = strlen(lt);
    char unit = lt[len - 1];
    int val = atoi(lt);
    if (val < 0) val = 0;
    if (unit == 'h' || unit == 'H') {
        return val * 60;
    } else if (unit == 'm' || unit == 'M') {
        return val;
    }
    return val; 
}


static void format_minutes_to_leasetime(int minutes, char *out, size_t out_len)
{
    if (minutes < 0) minutes = 0;
    if (minutes > 60) {
        int hours = minutes / 60; 
        snprintf(out, out_len, "%dh", hours > 0 ? hours : 1);
    } else {
        snprintf(out, out_len, "%dm", minutes);
    }
}


static void fill_lan_dhcp_info(struct json_object *data_obj)
{
    struct uci_context *ctx = uci_alloc_context();
    if (!ctx) {
        LOG_ERROR("fill_lan_dhcp_info: alloc ctx failed\n");
        return;
    }

    int enable = 1;
    int start = 0;
    int limit = 0;
    int lease_minutes = 0;
    char lease_str[32] = {0};
    char val_buf[32] = {0};

    if (jmx_uci_get_value(ctx, "dhcp.lan.ignore", val_buf, sizeof(val_buf)) == 0) {
        if (strcmp(val_buf, "1") == 0) enable = 0;
    }
    if (jmx_uci_get_value(ctx, "dhcp.lan.start", val_buf, sizeof(val_buf)) == 0) {
        start = atoi(val_buf);
    }
    if (jmx_uci_get_value(ctx, "dhcp.lan.limit", val_buf, sizeof(val_buf)) == 0) {
        limit = atoi(val_buf);
    }
    if (jmx_uci_get_value(ctx, "dhcp.lan.leasetime", lease_str, sizeof(lease_str)) == 0) {
        lease_minutes = parse_leasetime_to_minutes(lease_str);
    }

    struct json_object *dhcp_obj = json_object_new_object();
    if (dhcp_obj) {
        json_object_object_add(dhcp_obj, "enable", json_object_new_int(enable));
        json_object_object_add(dhcp_obj, "start", json_object_new_int(start));
        json_object_object_add(dhcp_obj, "limit", json_object_new_int(limit));
        json_object_object_add(dhcp_obj, "leasetime", json_object_new_int(lease_minutes));
        json_object_object_add(data_obj, "dhcp", dhcp_obj);
    }

    uci_free_context(ctx);
}


static void append_lan_dhcp_to_response(struct json_object *data_obj)
{
    if (!data_obj) return;
    fill_lan_dhcp_info(data_obj);
}


static int update_lan_dhcp_from_req(struct json_object *dhcp_obj)
{
    

    if (!dhcp_obj) return 0; 
	
    
    struct uci_context *ctx = uci_alloc_context();
    if (!ctx) {
        LOG_ERROR("update_lan_dhcp_from_req: alloc ctx failed\n");
        return -1;
    }
	
    

    struct json_object *enable_obj = json_object_object_get(dhcp_obj, "enable");
    struct json_object *start_obj = json_object_object_get(dhcp_obj, "start");
    struct json_object *limit_obj = json_object_object_get(dhcp_obj, "limit");
    struct json_object *lt_obj = json_object_object_get(dhcp_obj, "leasetime");
    

    if (enable_obj) {
        int en = json_object_get_int(enable_obj);
        jmx_uci_set_value(ctx, "dhcp.lan.ignore", en ? "0" : "1");
    }
    if (start_obj) {
        char buf[16];
        snprintf(buf, sizeof(buf), "%d", json_object_get_int(start_obj));
        jmx_uci_set_value(ctx, "dhcp.lan.start", buf);
    }
    if (limit_obj) {
        char buf[16];
        snprintf(buf, sizeof(buf), "%d", json_object_get_int(limit_obj));
        jmx_uci_set_value(ctx, "dhcp.lan.limit", buf);
    }
    if (lt_obj) {
        int minutes = json_object_get_int(lt_obj);
        char lease_buf[32];
        format_minutes_to_leasetime(minutes, lease_buf, sizeof(lease_buf));
        jmx_uci_set_value(ctx, "dhcp.lan.leasetime", lease_buf);
    }
    

    jmx_uci_commit(ctx, "dhcp");
    uci_free_context(ctx);
    return 0;
}
#endif
