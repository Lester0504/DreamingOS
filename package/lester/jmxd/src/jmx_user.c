#include "proc_path.h"

// SPDX-License-Identifier: GPL-2.0-or-later
/* 
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>  
*/
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <libubox/uloop.h>
#include <libubox/utils.h>
#include <libubus.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <json-c/json.h>
#include <linux/socket.h>
#include <sys/socket.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>
#include <uci.h>
#include <ctype.h>
#include "jmx_config.h"
#include "jmx.h"
#include "jmx_user.h"
#include "jmx_utils.h"
#include "jmx_netconfig_db.h"
#include "jmx_storage_guard.h"


LIST_HEAD(client_list);
int g_cur_user_num = 0;


static int g_app_valid_time = 300; 

unsigned long long g_daily_type_stats[MAX_APP_TYPE] = {0};
u_int32_t g_daily_stat_date = 0;  


LIST_HEAD(global_hourly_records);


traffic_stat_t g_global_hourly_traffic[HOURS_PER_DAY] = {{0}};
u_int32_t g_global_traffic_date = 0;  


#define CLIENT_DATA_BASE_DIR_DEFAULT "/tmp/jmx/client_data"

static char g_client_data_base_dir[256] = {0};
static int g_client_data_base_dir_initialized = 0;

static void mac_to_dirname(const char *mac, char *dirname, size_t len);
static int ensure_dir_exists(const char *path);
static void get_date_string(u_int32_t timestamp, char *date_str, size_t len);
static void format_time_string(u_int32_t timestamp, char *time_str, size_t len);
static void cleanup_old_record_files(void);
static u_int32_t parse_date_string(const char *date_str);
static int extract_date_from_filename(const char *filename, char *date_str, size_t len);

const char *get_client_data_base_dir(void) {
    if (!g_client_data_base_dir_initialized) {
        jmx_legacy_settings_t settings;
        if (jmx_legacy_settings_get(&settings) == 0 && settings.history_data_path[0]) {
            snprintf(g_client_data_base_dir, sizeof(g_client_data_base_dir),
                     "%s/client_data", settings.history_data_path);
        } else {
            strncpy(g_client_data_base_dir, CLIENT_DATA_BASE_DIR_DEFAULT, sizeof(g_client_data_base_dir) - 1);
        }
        g_client_data_base_dir[sizeof(g_client_data_base_dir) - 1] = '\0';
        g_client_data_base_dir_initialized = 1;
    }
    return g_client_data_base_dir;
}

void reset_client_data_base_dir_cache(void) {
    g_client_data_base_dir_initialized = 0;
    g_client_data_base_dir[0] = '\0';
}


void load_app_valid_time_config(void) {
    jmx_legacy_settings_t settings;
    if (jmx_legacy_settings_get(&settings) == 0 && settings.app_valid_time > 0)
        g_app_valid_time = settings.app_valid_time;
    else
        g_app_valid_time = 300;
    LOG_DEBUG("Loaded app_valid_time config: %d seconds\n", g_app_valid_time);
}


int get_app_valid_time(void) {
    return g_app_valid_time;
}

static int find_oldest_date_in_dir(const char *dir_path, char *oldest_date, size_t date_len) {
    DIR *base_dir = opendir(dir_path);
    if (!base_dir) {
        return -1;
    }
    
    char oldest[32] = {0};
    int found = 0;
    struct dirent *client_entry;
    
    while ((client_entry = readdir(base_dir)) != NULL) {
        if (client_entry->d_name[0] == '.')
            continue;
        
        char client_dir[512] = {0};
        snprintf(client_dir, sizeof(client_dir), "%s/%s", dir_path, client_entry->d_name);
        
        struct stat st;
        if (stat(client_dir, &st) != 0 || !S_ISDIR(st.st_mode))
            continue;
        
        char stats_dir[512] = {0};
        snprintf(stats_dir, sizeof(stats_dir), "%s/stats", client_dir);
        
        DIR *stats_d = opendir(stats_dir);
        if (stats_d) {
            struct dirent *file_entry;
            while ((file_entry = readdir(stats_d)) != NULL) {
                if (file_entry->d_name[0] == '.')
                    continue;
                
                char date_str[32] = {0};
                if (extract_date_from_filename(file_entry->d_name, date_str, sizeof(date_str)) == 0) {
                    if (!found || strcmp(date_str, oldest) < 0) {
                        strncpy(oldest, date_str, sizeof(oldest) - 1);
                        found = 1;
                    }
                }
            }
            closedir(stats_d);
        }
        
        char visits_dir[512] = {0};
        snprintf(visits_dir, sizeof(visits_dir), "%s/visits", client_dir);
        
        DIR *visits_d = opendir(visits_dir);
        if (visits_d) {
            struct dirent *file_entry;
            while ((file_entry = readdir(visits_d)) != NULL) {
                if (file_entry->d_name[0] == '.')
                    continue;
                
                char date_str[32] = {0};
                if (strlen(file_entry->d_name) > 4 && 
                    strcmp(file_entry->d_name + strlen(file_entry->d_name) - 4, ".txt") == 0) {
                    strncpy(date_str, file_entry->d_name, strlen(file_entry->d_name) - 4);
                    date_str[strlen(file_entry->d_name) - 4] = '\0';
                } else {
                    strncpy(date_str, file_entry->d_name, sizeof(date_str) - 1);
                }
                
                if (strlen(date_str) > 0) {
                    if (!found || strcmp(date_str, oldest) < 0) {
                        strncpy(oldest, date_str, sizeof(oldest) - 1);
                        found = 1;
                    }
                }
            }
            closedir(visits_d);
        }
    }
    
    closedir(base_dir);
    
    char global_stats_dir[512] = {0};
    snprintf(global_stats_dir, sizeof(global_stats_dir), "%s/global/stats", dir_path);
    
    DIR *global_stats_d = opendir(global_stats_dir);
    if (global_stats_d) {
        struct dirent *file_entry;
        while ((file_entry = readdir(global_stats_d)) != NULL) {
            if (file_entry->d_name[0] == '.')
                continue;
            
            char date_str[32] = {0};
            if (extract_date_from_filename(file_entry->d_name, date_str, sizeof(date_str)) == 0) {
                if (!found || strcmp(date_str, oldest) < 0) {
                    strncpy(oldest, date_str, sizeof(oldest) - 1);
                    found = 1;
                }
            }
        }
        closedir(global_stats_d);
    }
    
    if (found) {
        strncpy(oldest_date, oldest, date_len - 1);
        oldest_date[date_len - 1] = '\0';
        return 0;
    }
    
    return -1;
}

static void delete_date_files(const char *date_str) {
    DIR *base_dir = opendir(get_client_data_base_dir());
    if (!base_dir) {
        return;
    }
    
    struct dirent *client_entry;
    while ((client_entry = readdir(base_dir)) != NULL) {
        if (client_entry->d_name[0] == '.')
            continue;
        
        char client_dir[512] = {0};
        snprintf(client_dir, sizeof(client_dir), "%s/%s", get_client_data_base_dir(), client_entry->d_name);
        
        struct stat st;
        if (stat(client_dir, &st) != 0 || !S_ISDIR(st.st_mode))
            continue;
        
        char stats_dir[512] = {0};
        snprintf(stats_dir, sizeof(stats_dir), "%s/stats", client_dir);
        
        DIR *stats_d = opendir(stats_dir);
        if (!stats_d)
            continue;
        
        struct dirent *file_entry;
        while ((file_entry = readdir(stats_d)) != NULL) {
            if (file_entry->d_name[0] == '.')
                continue;
            
            char file_date[32] = {0};
            if (extract_date_from_filename(file_entry->d_name, file_date, sizeof(file_date)) == 0) {
                if (strcmp(file_date, date_str) == 0) {
                    char file_path[512] = {0};
                    snprintf(file_path, sizeof(file_path), "%s/%s", stats_dir, file_entry->d_name);
                    unlink(file_path);
                }
            }
        }
        closedir(stats_d);
        
        char visits_dir[512] = {0};
        snprintf(visits_dir, sizeof(visits_dir), "%s/visits", client_dir);
        
        DIR *visits_d = opendir(visits_dir);
        if (!visits_d)
            continue;
        
        while ((file_entry = readdir(visits_d)) != NULL) {
            if (file_entry->d_name[0] == '.')
                continue;
            
            char file_date[32] = {0};
            if (strlen(file_entry->d_name) > 4 && 
                strcmp(file_entry->d_name + strlen(file_entry->d_name) - 4, ".txt") == 0) {
                strncpy(file_date, file_entry->d_name, strlen(file_entry->d_name) - 4);
                file_date[strlen(file_entry->d_name) - 4] = '\0';
            } else {
                strncpy(file_date, file_entry->d_name, sizeof(file_date) - 1);
            }
            
            if (strcmp(file_date, date_str) == 0) {
                char file_path[512] = {0};
                snprintf(file_path, sizeof(file_path), "%s/%s", visits_dir, file_entry->d_name);
                unlink(file_path);
            }
        }
        closedir(visits_d);
    }
    
    closedir(base_dir);
}

static void cleanup_expired_files_by_days(void) {
    jmx_legacy_settings_t settings;
    if (jmx_legacy_settings_get(&settings) != 0)
        return;
    int record_time = settings.record_time;
    LOG_INFO("cleanup_expired_files_by_days: record_time: %d\n", record_time);
    if (record_time <= 0) {
        return;
    }
    
    time_t now = time(NULL);
    u_int32_t expire_timestamp = (u_int32_t)now - (record_time * SECONDS_PER_DAY);
    
    DIR *base_dir = opendir(get_client_data_base_dir());
    if (!base_dir) {
        return;
    }
    
    struct dirent *client_entry;
    int deleted_count = 0;
    
    while ((client_entry = readdir(base_dir)) != NULL) {
        if (client_entry->d_name[0] == '.')
            continue;
        
        char client_dir[512] = {0};
        snprintf(client_dir, sizeof(client_dir), "%s/%s", get_client_data_base_dir(), client_entry->d_name);
        
        struct stat st;
        if (stat(client_dir, &st) != 0 || !S_ISDIR(st.st_mode))
            continue;
        
        char stats_dir[512] = {0};
        snprintf(stats_dir, sizeof(stats_dir), "%s/stats", client_dir);
        
        DIR *stats_d = opendir(stats_dir);
        if (stats_d) {
            struct dirent *file_entry;
            while ((file_entry = readdir(stats_d)) != NULL) {
                if (file_entry->d_name[0] == '.')
                    continue;
                
                char date_str[32] = {0};
                if (extract_date_from_filename(file_entry->d_name, date_str, sizeof(date_str)) == 0) {
                    u_int32_t file_date = parse_date_string(date_str);
                    if (file_date > 0 && file_date < expire_timestamp) {
                        char file_path[512] = {0};
                        snprintf(file_path, sizeof(file_path), "%s/%s", stats_dir, file_entry->d_name);
                        if (unlink(file_path) == 0) {
                            deleted_count++;
                        }
                    }
                }
            }
            closedir(stats_d);
        }
        
        char visits_dir[512] = {0};
        snprintf(visits_dir, sizeof(visits_dir), "%s/visits", client_dir);
        
        DIR *visits_d = opendir(visits_dir);
        if (visits_d) {
            struct dirent *file_entry;
            while ((file_entry = readdir(visits_d)) != NULL) {
                if (file_entry->d_name[0] == '.')
                    continue;
                
                char file_date[32] = {0};
                if (strlen(file_entry->d_name) > 4 && 
                    strcmp(file_entry->d_name + strlen(file_entry->d_name) - 4, ".txt") == 0) {
                    strncpy(file_date, file_entry->d_name, strlen(file_entry->d_name) - 4);
                    file_date[strlen(file_entry->d_name) - 4] = '\0';
                } else {
                    strncpy(file_date, file_entry->d_name, sizeof(file_date) - 1);
                }
                
                u_int32_t file_date_ts = parse_date_string(file_date);
                if (file_date_ts > 0 && file_date_ts < expire_timestamp) {
                    char file_path[512] = {0};
                    snprintf(file_path, sizeof(file_path), "%s/%s", visits_dir, file_entry->d_name);
                    if (unlink(file_path) == 0) {
                        deleted_count++;
                    }
                }
            }
            closedir(visits_d);
        }
    }
    
    closedir(base_dir);
    
    char global_stats_dir[512] = {0};
    snprintf(global_stats_dir, sizeof(global_stats_dir), "%s/global/stats", get_client_data_base_dir());
    
    DIR *global_stats_d = opendir(global_stats_dir);
    if (global_stats_d) {
        struct dirent *file_entry;
        while ((file_entry = readdir(global_stats_d)) != NULL) {
            if (file_entry->d_name[0] == '.')
                continue;
            
            char date_str[32] = {0};
            if (extract_date_from_filename(file_entry->d_name, date_str, sizeof(date_str)) == 0) {
                u_int32_t file_date = parse_date_string(date_str);
                if (file_date > 0 && file_date < expire_timestamp) {
                    char file_path[512] = {0};
                    snprintf(file_path, sizeof(file_path), "%s/%s", global_stats_dir, file_entry->d_name);
                    if (unlink(file_path) == 0) {
                        deleted_count++;
                    }
                }
            }
        }
        closedir(global_stats_d);
    }
    
    if (deleted_count > 0) {
        LOG_INFO("Cleaned up %d expired files (record_time: %d days)\n", deleted_count, record_time);
    }
}

void check_and_cleanup_history_data_by_size(void) {
    LOG_INFO("check_and_cleanup_history_data_by_size: start\n");
    cleanup_expired_files_by_days();
    
    jmx_legacy_settings_t settings;
    if (jmx_legacy_settings_get(&settings) != 0)
        return;
    const char *history_data_size = settings.history_data_size;
    const char *history_data_path = settings.history_data_path;
    
    if (strlen(history_data_size) == 0) {
        return;
    }
    
    char *endptr = NULL;
    long max_size_mb = strtol(history_data_size, &endptr, 10);
    if (*endptr != '\0' || max_size_mb <= 0) {
        return;
    }
    
    char data_dir[512] = {0};
    if (strlen(history_data_path) > 0) {
        snprintf(data_dir, sizeof(data_dir), "%s/client_data", history_data_path);
    } else {
        strncpy(data_dir, CLIENT_DATA_BASE_DIR_DEFAULT, sizeof(data_dir) - 1);
    }
    
    char cmd[1024] = {0};
    char result[256] = {0};
    snprintf(cmd, sizeof(cmd), "du -sm %s 2>/dev/null | awk '{print $1}'", data_dir);
    if (exec_with_result_line(cmd, result, sizeof(result)) != 0 || strlen(result) == 0) {
        return;
    }
    
    unsigned long long current_size_mb = strtoull(result, NULL, 10);
    
    if (current_size_mb <= (unsigned long long)max_size_mb) {
        return;
    }
    
    char oldest_date[32] = {0};
    if (find_oldest_date_in_dir(data_dir, oldest_date, sizeof(oldest_date)) == 0) {
        delete_date_files(oldest_date);
        LOG_INFO("Cleaned up oldest date files: %s (current size: %llu MB, max: %ld MB)\n", 
                 oldest_date, current_size_mb, max_size_mb);
    }
}

int get_timestamp(void)
{
    struct timeval cur_time;
    gettimeofday(&cur_time, NULL);
    return cur_time.tv_sec;
}




void add_visit_info_node(struct list_head *visit_list, visit_info_t *node)
{
    if (!visit_list || !node)
        return;


    list_add(&node->visit, visit_list);
}

void init_client_list(void)
{
    INIT_LIST_HEAD(&client_list);
    printf("init client list ok...\n");
}

static void client_lower_mac(const char *in, char *out, size_t out_len)
{
    char hex[13];
    int n = 0;
    size_t i;

    if (!out || out_len == 0)
        return;
    out[0] = '\0';
    if (!in || out_len < 18)
        return;
    for (i = 0; in[i] && n < 12; i++) {
        if (isxdigit((unsigned char)in[i]))
            hex[n++] = (char)tolower((unsigned char)in[i]);
        else if (in[i] == ':' || in[i] == '-' || in[i] == '.' ||
                 isspace((unsigned char)in[i]))
            continue;
        else
            return;
    }
    if (n != 12)
        return;
    hex[12] = '\0';
    snprintf(out, out_len, "%c%c:%c%c:%c%c:%c%c:%c%c:%c%c",
             hex[0], hex[1], hex[2], hex[3], hex[4], hex[5],
             hex[6], hex[7], hex[8], hex[9], hex[10], hex[11]);
}

#define CLIENT_IFACE_CACHE_MAX 32
#define CLIENT_IFACE_CACHE_TTL 30

static char g_client_lan_ifaces[CLIENT_IFACE_CACHE_MAX][32];
static char g_client_wan_ifaces[CLIENT_IFACE_CACHE_MAX][32];
static int g_client_lan_iface_count;
static int g_client_wan_iface_count;
static u_int32_t g_client_iface_cache_at;

static int client_iface_list_has(char list[][32], int count, const char *ifname)
{
    int i;

    if (!ifname || !ifname[0])
        return 0;
    for (i = 0; i < count; i++)
        if (!strcmp(list[i], ifname))
            return 1;
    return 0;
}

static void client_iface_list_add(char list[][32], int *count, const char *ifname)
{
    if (!count || !ifname || !ifname[0] || ifname[0] == '@' ||
        strlen(ifname) >= sizeof(list[0]) || *count >= CLIENT_IFACE_CACHE_MAX ||
        client_iface_list_has(list, *count, ifname))
        return;
    snprintf(list[*count], sizeof(list[*count]), "%s", ifname);
    (*count)++;
}

static int client_network_section_is_wan(const char *name, const char *role,
                                         const char *proto)
{
    return (name && (!strncmp(name, "wan", 3) || !strncmp(name, "wwan", 4))) ||
           (role && (!strcasecmp(role, "wan") || !strcasecmp(role, "primary") ||
                     !strcasecmp(role, "secondary") || !strcasecmp(role, "uplink"))) ||
           (proto && (!strcasecmp(proto, "pppoe") || !strcasecmp(proto, "pptp") ||
                      !strcasecmp(proto, "dslite") || !strcasecmp(proto, "464xlat")));
}

static int client_network_section_is_lan(const char *name, const char *role,
                                         const char *proto, const char *device,
                                         const char *ipaddr, const char *ip6assign)
{
    if ((name && (!strcmp(name, "lan") || !strncmp(name, "lan", 3) ||
                  !strncmp(name, "guest", 5) || !strncmp(name, "iot", 3))) ||
        (role && (!strcasecmp(role, "lan") || !strcasecmp(role, "guest") ||
                  !strcasecmp(role, "iot") || !strcasecmp(role, "client"))))
        return 1;
    return device && !strncmp(device, "br-", 3) && strncmp(device, "br-docker", 9) &&
           proto && !strcasecmp(proto, "static") &&
           ((ipaddr && ipaddr[0]) || (ip6assign && ip6assign[0]));
}

static void client_iface_add_bridge_members(const char *bridge)
{
    char path[160];
    DIR *dir;
    struct dirent *de;

    if (!bridge || !bridge[0])
        return;
    snprintf(path, sizeof(path), "/sys/class/net/%s/brif", bridge);
    dir = opendir(path);
    if (!dir)
        return;
    while ((de = readdir(dir)) != NULL) {
        if (de->d_name[0] == '.')
            continue;
        client_iface_list_add(g_client_lan_ifaces, &g_client_lan_iface_count,
                              de->d_name);
    }
    closedir(dir);
}

static void client_iface_cache_refresh(void)
{
    struct uci_context *ctx;
    struct uci_package *pkg = NULL;
    struct uci_element *e;
    int i;

    g_client_lan_iface_count = 0;
    g_client_wan_iface_count = 0;
    client_iface_list_add(g_client_lan_ifaces, &g_client_lan_iface_count, "br-lan");

    ctx = uci_alloc_context();
    if (ctx && uci_load(ctx, "network", &pkg) == UCI_OK) {
        uci_foreach_element(&pkg->sections, e) {
            struct uci_section *s = uci_to_section(e);
            const char *name;
            const char *device;
            const char *role;
            const char *proto;
            const char *ipaddr;
            const char *ip6assign;

            if (!s || strcmp(s->type, "interface"))
                continue;
            name = s->e.name ? s->e.name : "";
            device = uci_lookup_option_string(ctx, s, "device");
            role = uci_lookup_option_string(ctx, s, "dreamingwrt_role");
            proto = uci_lookup_option_string(ctx, s, "proto");
            ipaddr = uci_lookup_option_string(ctx, s, "ipaddr");
            ip6assign = uci_lookup_option_string(ctx, s, "ip6assign");
            if (client_network_section_is_wan(name, role, proto)) {
                client_iface_list_add(g_client_wan_ifaces,
                                      &g_client_wan_iface_count, name);
                client_iface_list_add(g_client_wan_ifaces,
                                      &g_client_wan_iface_count, device);
            } else if (client_network_section_is_lan(name, role, proto, device,
                                                     ipaddr, ip6assign)) {
                client_iface_list_add(g_client_lan_ifaces,
                                      &g_client_lan_iface_count, name);
                client_iface_list_add(g_client_lan_ifaces,
                                      &g_client_lan_iface_count, device);
            }
        }
    }
    if (pkg)
        uci_unload(ctx, pkg);
    if (ctx)
        uci_free_context(ctx);

    for (i = 0; i < g_client_lan_iface_count; i++)
        client_iface_add_bridge_members(g_client_lan_ifaces[i]);
    g_client_iface_cache_at = get_timestamp();
}

static int client_iface_is_lan(const char *ifname)
{
    char path[160];
    char target[256];
    const char *master;
    ssize_t n;
    u_int32_t now = get_timestamp();

    if (!ifname || !ifname[0])
        return 0;
    if (!g_client_iface_cache_at || now - g_client_iface_cache_at >= CLIENT_IFACE_CACHE_TTL)
        client_iface_cache_refresh();
    if (client_iface_list_has(g_client_wan_ifaces, g_client_wan_iface_count, ifname))
        return 0;
    if (client_iface_list_has(g_client_lan_ifaces, g_client_lan_iface_count, ifname))
        return 1;

    snprintf(path, sizeof(path), "/sys/class/net/%s/master", ifname);
    n = readlink(path, target, sizeof(target) - 1);
    if (n <= 0)
        return 0;
    target[n] = '\0';
    master = strrchr(target, '/');
    master = master ? master + 1 : target;
    return client_iface_list_has(g_client_lan_ifaces, g_client_lan_iface_count,
                                 master);
}

static int client_ipv6_is_link_local(const char *addr)
{
    return addr && addr[0] && !strncasecmp(addr, "fe80:", 5);
}

static int client_ipv6_is_ula(const char *addr)
{
    return addr && addr[0] &&
           (!strncasecmp(addr, "fc", 2) || !strncasecmp(addr, "fd", 2));
}

static int client_ipv6_is_loopback(const char *addr)
{
    return addr && (!strcmp(addr, "::1") || !strcasecmp(addr, "0:0:0:0:0:0:0:1"));
}

static int client_ipv6_is_usable(const char *addr)
{
    return addr && addr[0] && strchr(addr, ':') && !client_ipv6_is_loopback(addr);
}

static void client_append_ipv6_addr(client_node_t *node, const char *addr)
{
    char needle[160];
    size_t used;

    if (!node || !client_ipv6_is_usable(addr))
        return;
    snprintf(needle, sizeof(needle), "|%s|", addr);
    if (strstr(node->ipv6_addrs, needle))
        return;
    used = strlen(node->ipv6_addrs);
    if (used + strlen(addr) + 3 >= sizeof(node->ipv6_addrs))
        return;
    snprintf(node->ipv6_addrs + used, sizeof(node->ipv6_addrs) - used,
             "%s%s|", used == 0 ? "|" : "", addr);
}

static void client_set_ipv6_evidence(client_node_t *node, const char *addr,
                                     const char *state)
{
    if (!node || !client_ipv6_is_usable(addr))
        return;
    client_append_ipv6_addr(node, addr);
    if (!node->ipv6[0])
        snprintf(node->ipv6, sizeof(node->ipv6), "%s", addr);
    if (client_ipv6_is_link_local(addr)) {
        if (!node->ipv6_link_local[0])
            snprintf(node->ipv6_link_local, sizeof(node->ipv6_link_local), "%s", addr);
    } else if (client_ipv6_is_ula(addr)) {
        if (!node->ipv6_lan[0])
            snprintf(node->ipv6_lan, sizeof(node->ipv6_lan), "%s", addr);
    } else if (!node->ipv6_global[0]) {
        snprintf(node->ipv6_global, sizeof(node->ipv6_global), "%s", addr);
    }
    if (state && state[0])
        snprintf(node->neigh_state, sizeof(node->neigh_state), "%s", state);
}

static int client_neigh_state_observed(const char *state)
{
    return state && state[0] &&
           (strstr(state, "REACHABLE") || strstr(state, "STALE") ||
            strstr(state, "DELAY") || strstr(state, "PROBE") ||
            strstr(state, "PERMANENT") || strstr(state, "NOARP"));
}

static int client_neigh_state_marks_online(const char *state)
{
    return state && state[0] &&
           (strstr(state, "REACHABLE") || strstr(state, "DELAY") ||
            strstr(state, "PROBE") || strstr(state, "PERMANENT") ||
            strstr(state, "NOARP"));
}

static void client_last_token(const char *line, char *out, size_t out_len)
{
    size_t end;
    size_t start;
    size_t len;

    if (!out || out_len == 0)
        return;
    out[0] = '\0';
    if (!line)
        return;
    end = strlen(line);
    while (end > 0 && isspace((unsigned char)line[end - 1]))
        end--;
    start = end;
    while (start > 0 && !isspace((unsigned char)line[start - 1]))
        start--;
    len = end > start ? end - start : 0;
    if (len == 0)
        return;
    if (len >= out_len)
        len = out_len - 1;
    memcpy(out, line + start, len);
    out[len] = '\0';
}

static void client_set_ipv4_evidence(client_node_t *node, const char *ip,
                                     const char *state)
{
    if (!node || !ip || !ip[0])
        return;
    if (strcmp(ip, "0.0.0.0"))
        snprintf(node->ip, sizeof(node->ip), "%s", ip);
    if (state && state[0])
        snprintf(node->neigh_state, sizeof(node->neigh_state), "%s", state);
}

static void client_mark_online(client_node_t *node, const char *source)
{
    u_int32_t now = get_timestamp();

    if (!node)
        return;
    if (!node->online &&
        (!node->online_time || !node->offline_time || now - node->offline_time > 10))
        node->online_time = now;
    node->online = 1;
    node->offline_time = 0;
    node->last_seen_ts = now;
    node->runtime_updated_at = now;
    if (source && source[0])
        snprintf(node->online_source, sizeof(node->online_source), "%s", source);
}

client_node_t *add_client_node(const char *mac)
{
	int j;
    client_node_t *node = (client_node_t *)calloc(1, sizeof(client_node_t));
    if (!node)
        return NULL;
    strncpy(node->mac, mac, sizeof(node->mac));
    node->online = 1;
    node->online_time = get_timestamp();
    node->last_seen_ts = node->online_time;
    node->runtime_updated_at = node->online_time;
    snprintf(node->online_source, sizeof(node->online_source), "%s", "created");

    node->ipv6[0] = '\0';
    node->ipv6_global[0] = '\0';
    node->ipv6_lan[0] = '\0';
    node->ipv6_link_local[0] = '\0';
    node->ipv6_addrs[0] = '\0';
    node->neigh_state[0] = '\0';
    node->up_rate = 0;
    node->down_rate = 0;
    node->active = 0;  

    INIT_LIST_HEAD(&node->online_visit);
    INIT_LIST_HEAD(&node->visit);

    INIT_LIST_HEAD(&node->stat_list);

    INIT_LIST_HEAD(&node->online_offline_records);

    INIT_LIST_HEAD(&node->client);

    u_int32_t today = get_today_start_timestamp();
    node->daily_stats.date = today;
    node->daily_stats.is_today = 1;
    for (j = 0; j < HOURS_PER_DAY; j++) {
        for (int k = 0; k < TOP_APP_PER_HOUR; k++) {
            node->daily_stats.hourly_top_apps[j][k] = -1;
        }
    }
    

    node->daily_top_apps_stats.date = today;
    node->daily_top_apps_stats.is_today = 1;
    node->daily_top_apps_stats.count = 0;
    for (j = 0; j < MAX_TOP_APPS_PER_DAY; j++) {
        node->daily_top_apps_stats.apps[j].appid = -1;
        node->daily_top_apps_stats.apps[j].total_time = 0;
    }

    list_add(&node->client, &client_list);
    g_cur_user_num++;
    printf("add mac:%s to client list....success\n", mac);
    return node;
}

client_node_t *find_client_node(const char *mac)
{
    client_node_t *p = NULL;
    char wanted[MAX_MAC_LEN] = {0};

    client_lower_mac(mac, wanted, sizeof(wanted));
    
    list_for_each_entry(p, &client_list, client) {
        char have[MAX_MAC_LEN] = {0};

        client_lower_mac(p->mac, have, sizeof(have));
        if ((wanted[0] && have[0] && !strcmp(have, wanted)) ||
            (!wanted[0] && mac && 0 == strncmp(p->mac, mac, sizeof(p->mac))))
        {
            return p;
        }
    }
    return NULL;
}

void client_foreach(void *arg, iter_func iter)
{
    client_node_t *node = NULL;
    int count = 0;

    LOG_DEBUG("client_foreach: Starting iteration over client_list...\n");
    list_for_each_entry(node, &client_list, client) {
        count++;
        LOG_DEBUG("client_foreach: Processing client[%d] - mac=%s, online=%d\n", 
               count, node->mac, node->online);
        iter(arg, node);
    }
    LOG_DEBUG("client_foreach: Finished iteration, processed %d clients\n", count);
}

char *format_time(int timetamp)
{
    char time_buf[64] = {0};
    time_t seconds = timetamp;
    struct tm *auth_tm = localtime(&seconds);
    strftime(time_buf, sizeof(time_buf), "%Y %m %d %H:%M:%S", auth_tm);
    return strdup(time_buf);
}

void update_client_hostname(void)
{
    char line_buf[256] = {0};
    char hostname_buf[128] = {0};
    char mac_buf[32] = {0};
    char ip_buf[32] = {0};

    FILE *fp = fopen("/tmp/dhcp.leases", "r");
    if (!fp)
    {
        printf("open dhcp lease file....failed\n");
        return;
    }
    while (fgets(line_buf, sizeof(line_buf), fp))
    {
        if (strlen(line_buf) <= 16)
            continue;
        sscanf(line_buf, "%*s %s %s %s", mac_buf, ip_buf, hostname_buf);
        client_node_t *node = find_client_node(mac_buf);
        if (!node)
        {
            node = add_client_node(mac_buf);
            strncpy(node->ip, ip_buf, sizeof(node->ip));
            node->online = 0;
            node->offline_time = get_timestamp();
        }

        if (strlen(hostname_buf) > 0 && hostname_buf[0] != '*')
        {
            strncpy(node->hostname, hostname_buf, sizeof(node->hostname));
        }
    }
    fclose(fp);
}

void clean_client_nickname_iter(void *arg, client_node_t *client)
{
    client->nickname[0] = '\0';
}

void clean_client_nickname(void)
{
    client_foreach(NULL, clean_client_nickname_iter);
}

static int update_client_nickname_from_db(const char *mac, const char *nickname,
                                          void *arg)
{
    client_node_t *node;
    (void)arg;

    node = find_client_node((char *)mac);
    if (!node)
        return 0;
    snprintf(node->nickname, sizeof(node->nickname), "%s", nickname ? nickname : "");
    return 0;
}

void update_client_nickname(void)
{
    clean_client_nickname();
    if (jmx_client_nickname_foreach(update_client_nickname_from_db, NULL) != 0)
        LOG_ERROR("Failed to refresh client nicknames from config.db\n");
}



void clean_client_online_status(void)
{
    client_node_t *node = NULL;

    list_for_each_entry(node, &client_list, client) {
        node->up_rate = 0;
        node->down_rate = 0;
        node->ipv6[0] = '\0';
        node->ipv6_global[0] = '\0';
        node->ipv6_lan[0] = '\0';
        node->ipv6_link_local[0] = '\0';
        node->ipv6_addrs[0] = '\0';
        node->neigh_state[0] = '\0';
        if (node->online)
        {
            node->offline_time = get_timestamp();
            node->online = 0;
        }
    }
}


void update_client_from_kernel(void)
{
    char line_buf[256] = {0};
    char mac_buf[32] = {0};
    char ip_buf[32] = {0};
    char ipv6_buf[128] = {0};
    unsigned int up_rate = 0;
    unsigned int down_rate = 0;

    clean_client_online_status();

    FILE *fp = jmx_fopen_af("af_client", "r");
    if (!fp)
    {
        LOG_DEBUG("open client file....failed\n");
        goto ipv6_neigh;
    }
    fgets(line_buf, sizeof(line_buf), fp); // title
    while (fgets(line_buf, sizeof(line_buf), fp))
    {
        int id;
        int parsed = sscanf(line_buf, "%d %s %s %s %u %u", &id, mac_buf, ip_buf, ipv6_buf, &up_rate, &down_rate);
        LOG_DEBUG("update_client_from_kernel: parsed = %d, line_buf = %s\n", parsed, line_buf);
        if (parsed < 3) 
        {
            printf("invalid line format:%s\n", line_buf);
            continue;
        }
        if (strlen(mac_buf) < 17)
        {
            printf("invalid mac:%s\n", mac_buf);
            continue;
        }
        client_node_t *node = find_client_node(mac_buf);
        if (!node)
        {
            node = add_client_node(mac_buf);
            if (!node)
                continue;
            strncpy(node->ip, ip_buf, sizeof(node->ip));
        }

        strncpy(node->ip, ip_buf, sizeof(node->ip));

        if (parsed >= 4 && strlen(ipv6_buf) > 0)
        {
            client_set_ipv6_evidence(node, ipv6_buf, "af_client");
            LOG_DEBUG("update_client_from_kernel: ipv6 = %s\n", ipv6_buf);
        }

        if (parsed >= 5)
        {
            node->up_rate = up_rate;
            LOG_DEBUG("update_client_from_kernel: up_rate = %d\n", up_rate);
        }
        else
        {
            node->up_rate = 0;
            LOG_DEBUG("update_client_from_kernel: up_rate = 0\n");
        }
        if (parsed >= 6)
        {
            node->down_rate = down_rate;
            LOG_DEBUG("update_client_from_kernel: down_rate = %d\n", down_rate);
        }
        else
        {
            node->down_rate = 0;
        }
        client_mark_online(node, "af_client");
    }
    fclose(fp);

ipv6_neigh:
    fp = popen("ip -6 neigh show 2>/dev/null", "r");
    if (!fp)
        goto ipv4_neigh;
    while (fgets(line_buf, sizeof(line_buf), fp)) {
        char addr[128] = {0};
        char dev[32] = {0};
        char mac_raw[64] = {0};
        char mac_l[MAX_MAC_LEN] = {0};
        char state[32] = {0};
        char *p;
        client_node_t *node;

        if (sscanf(line_buf, "%127s dev %31s", addr, dev) < 2)
            continue;
        if (!client_iface_is_lan(dev))
            continue;
        p = strstr(line_buf, " lladdr ");
        if (!p)
            continue;
        if (sscanf(p + 8, "%63s", mac_raw) != 1)
            continue;
        client_lower_mac(mac_raw, mac_l, sizeof(mac_l));
        if (!mac_l[0])
            continue;
        state[0] = '\0';
        client_last_token(line_buf, state, sizeof(state));
        if (!state[0])
            snprintf(state, sizeof(state), "%s", "unknown");
        if (!client_neigh_state_observed(state))
            continue;
        node = find_client_node(mac_l);
        if (!node) {
            if (!client_neigh_state_marks_online(state))
                continue;
            node = add_client_node(mac_l);
            if (!node)
                continue;
            node->ip[0] = '\0';
        }
        client_set_ipv6_evidence(node, addr, state);
        if (client_neigh_state_marks_online(state))
            client_mark_online(node, "ip6_neigh");
    }
    pclose(fp);

ipv4_neigh:
    fp = popen("ip -4 neigh show 2>/dev/null", "r");
    if (fp) {
        while (fgets(line_buf, sizeof(line_buf), fp)) {
            char addr[64] = {0};
            char dev[32] = {0};
            char mac_raw[64] = {0};
            char mac_l[MAX_MAC_LEN] = {0};
            char state[32] = {0};
            char *p;
            client_node_t *node;

            if (sscanf(line_buf, "%63s dev %31s", addr, dev) < 2)
                continue;
            if (!client_iface_is_lan(dev))
                continue;
            p = strstr(line_buf, " lladdr ");
            if (!p)
                continue;
            if (sscanf(p + 8, "%63s", mac_raw) != 1)
                continue;
            client_lower_mac(mac_raw, mac_l, sizeof(mac_l));
            if (!mac_l[0])
                continue;
            client_last_token(line_buf, state, sizeof(state));
            if (!state[0])
                snprintf(state, sizeof(state), "%s", "unknown");
            if (!client_neigh_state_observed(state))
                continue;
            node = find_client_node(mac_l);
            if (!node) {
                if (!client_neigh_state_marks_online(state))
                    continue;
                node = add_client_node(mac_l);
                if (!node)
                    continue;
            }
            client_set_ipv4_evidence(node, addr, state);
            if (client_neigh_state_marks_online(state))
                client_mark_online(node, "ip4_neigh");
        }
        pclose(fp);
    }

    fp = fopen("/proc/net/arp", "r");
    if (!fp)
        return;
    fgets(line_buf, sizeof(line_buf), fp);
    while (fgets(line_buf, sizeof(line_buf), fp)) {
        char ip[64] = {0};
        char flags[16] = {0};
        char mac_raw[64] = {0};
        char dev[32] = {0};
        char mac_l[MAX_MAC_LEN] = {0};
        client_node_t *node;

        if (sscanf(line_buf, "%63s %*s %15s %63s %*s %31s",
                   ip, flags, mac_raw, dev) < 4)
            continue;
        if (strcmp(flags, "0x2") && strcmp(flags, "0x6"))
            continue;
        if (!client_iface_is_lan(dev))
            continue;
        client_lower_mac(mac_raw, mac_l, sizeof(mac_l));
        if (!mac_l[0])
            continue;
        node = find_client_node(mac_l);
        if (!node) {
            node = add_client_node(mac_l);
            if (!node)
                continue;
        }
        client_set_ipv4_evidence(node, ip, "arp_reachable");
        client_mark_online(node, "arp");
    }
    fclose(fp);
}

void update_client_online_status(void)
{
    update_client_from_kernel();
}

#define CLIENT_OFFLINE_TIME (SECONDS_PER_DAY * 3)

int check_client_expire(void)
{
    int count = 0;
    int cur_time = get_timestamp();
    int offline_time = 0;
    int expire_count = 0;
    int visit_count = 0;
    client_node_t *node = NULL;
    visit_info_t *p_info = NULL;

    list_for_each_entry(node, &client_list, client) {
        if (node->online)
            continue;
        visit_count = 0;
        offline_time = cur_time - node->offline_time;
        if (offline_time > CLIENT_OFFLINE_TIME)
        {
            node->expire = 1;
            list_for_each_entry(p_info, &node->visit, visit) {
                p_info->expire = 1;
                visit_count++;
            }
            expire_count++;
            LOG_WARN("client:%s expired, offline time = %ds, count=%d, visit_count=%d\n",
                   node->mac, offline_time, expire_count, visit_count);
        }
    }
    return expire_count;
}

void flush_expire_client_node(void)
{
    int count = 0;
    client_node_t *node = NULL, *tmp = NULL;
    visit_info_t *p_info = NULL, *tmp_info = NULL;
    visit_stat_t *stat_node = NULL, *tmp_stat_node = NULL;

    list_for_each_entry_safe(node, tmp, &client_list, client) {
        if (node->expire)
        {
            list_for_each_entry_safe(p_info, tmp_info, &node->online_visit, visit) {
                list_del(&p_info->visit);
                free(p_info);
            }

            list_for_each_entry_safe(p_info, tmp_info, &node->visit, visit) {
                list_del(&p_info->visit);
                free(p_info);
            }

            list_for_each_entry_safe(stat_node, tmp_stat_node, &node->stat_list, list) {
                list_del(&stat_node->list);
                free(stat_node);
            }
            list_del(&node->client);
            free(node);
            count++;
            g_cur_user_num--;
        }
    }
}

#define ONLINE_VISIT_TIMEOUT_SEC 300

void move_expired_online_visit_to_offline(void)
{
    int cur_time = get_timestamp();
    client_node_t *node = NULL;
    visit_info_t *p_info = NULL, *tmp_info = NULL;

    list_for_each_entry(node, &client_list, client) {
        list_for_each_entry_safe(p_info, tmp_info, &node->online_visit, visit) {
            int diff = cur_time - (int)p_info->latest_time;
            LOG_INFO("move_expired_online_visit_to_offline: mac = %s, diff = %d\n", node->mac, diff);
            if (diff > ONLINE_VISIT_TIMEOUT_SEC) {
                list_del(&p_info->visit);
                LOG_INFO("move_expired_online_visit_to_offline: mac = %s, appid = %d, action = %d, first_time = %d, latest_time = %d\n", node->mac, p_info->appid, p_info->action, p_info->first_time, p_info->latest_time);
                

                int total_time = p_info->latest_time - p_info->first_time;
                if (total_time < g_app_valid_time) {
                    LOG_DEBUG("Discard visit record (too short): mac=%s, appid=%d, duration=%ds < %ds\n", 
                              node->mac, p_info->appid, total_time, g_app_valid_time);
                    free(p_info); 
                } else {
                    p_info->expire = 0;
                    add_visit_info_node(&node->visit, p_info);
                }
            }
        }
    }
}

void update_client_visiting_info(void)
{
    char line_buf[256] = {0};
    char mac_buf[32] = {0};
    char url_buf[MAX_REPORT_URL_LEN] = {0};
    char app_buf[32] = {0};

    FILE *fp = jmx_fopen_af("af_visit", "r");
    if (!fp)
    {
        printf("open af_visit file....failed\n");
        return;
    }

    fgets(line_buf, sizeof(line_buf), fp); // title
    while (fgets(line_buf, sizeof(line_buf), fp))
    {
        memset(mac_buf, 0, sizeof(mac_buf));
        memset(app_buf, 0, sizeof(app_buf));
        memset(url_buf, 0, sizeof(url_buf));

        if (sscanf(line_buf, "%31s %31s %63s", mac_buf, app_buf, url_buf) < 2)
            continue;

        client_node_t *node = find_client_node(mac_buf);
        if (!node)
            continue;

        if (url_buf[0] == '\0' || strcmp(url_buf, "none") == 0)
            node->visiting_url[0] = '\0';
        else
            strncpy(node->visiting_url, url_buf, sizeof(node->visiting_url) - 1);

        node->visiting_app = atoi(app_buf);
    }

    fclose(fp);
}

void update_client_list(void)
{
    clean_client_online_status();
    update_client_hostname();
    update_client_nickname();
    update_client_online_status();
    update_client_visiting_info();
}


void dump_client_list(void)
{
    int count = 0;
    char hostname_buf[MAX_HOSTNAME_SIZE] = {0};
    char ip_buf[MAX_IP_LEN] = {0};

    FILE *fp = fopen(OAF_DEV_LIST_FILE, "w");
    if (!fp)
    {
        return;
    }
  
    fprintf(fp, "%-4s %-20s %-20s %-32s %-8s %-12s %-12s\n", 
            "Id", "Mac Addr", "Ip Addr", "Hostname", "Online", "OnlineTime", "OfflineTime");
    

    client_node_t *node = NULL;
    list_for_each_entry(node, &client_list, client) {
        if (node->online != 0)
        {
            if (strlen(node->hostname) == 0)
                strcpy(hostname_buf, "*");
            else
                strcpy(hostname_buf, node->hostname);
            if (strlen(node->ip) == 0)
                strcpy(ip_buf, "*");
            else
                strcpy(ip_buf, node->ip);
            fprintf(fp, "%-4d %-20s %-20s %-32s %-8d %-12u %-12u\n",
                    count + 1, node->mac, ip_buf, hostname_buf, node->online, 
                    node->online_time, node->offline_time);
            count++;
            if (count >= MAX_SUPPORT_DEV_NUM)
                goto EXIT;
        }
    }
    

    list_for_each_entry(node, &client_list, client) {
        if (node->online == 0)
        {
            if (strlen(node->hostname) == 0)
                strcpy(hostname_buf, "*");
            else
                strcpy(hostname_buf, node->hostname);

            if (strlen(node->ip) == 0)
                strcpy(ip_buf, "*");
            else
                strcpy(ip_buf, node->ip);

            fprintf(fp, "%-4d %-20s %-20s %-32s %-8d %-12u %-12u\n",
                    count + 1, node->mac, ip_buf, hostname_buf, node->online,
                    node->online_time, node->offline_time);
            count++;
            if (count >= MAX_SUPPORT_DEV_NUM)
                goto EXIT;
        }
    }
EXIT:
    fclose(fp);
}

#define MAX_RECORD_TIME (3 * 24 * 60 * 60) // 7day

#define RECORD_REMAIN_TIME (24 * 60 * 60) // 1day
#define INVALID_RECORD_TIME (5 * 60)      // 5min

void check_client_visit_info_expire(void)
{
    int count = 0;
    int cur_time = get_timestamp();
    client_node_t *node = NULL;
    visit_info_t *p_info = NULL, *tmp_info = NULL;

    list_for_each_entry(node, &client_list, client) {

        list_for_each_entry_safe(p_info, tmp_info, &node->visit, visit) {
            int total_time = p_info->latest_time - p_info->first_time;
            int interval_time = cur_time - p_info->first_time;
            if (interval_time > MAX_RECORD_TIME || interval_time < 0)
            {
                p_info->expire = 1;
            }
            else if (interval_time > RECORD_REMAIN_TIME)
            {
                if (total_time < INVALID_RECORD_TIME)
                    p_info->expire = 1;
            }
        }
    }
}

void flush_expire_visit_info(void)
{
    int count = 0;
    client_node_t *node = NULL;
    visit_info_t *p_info = NULL, *tmp_info = NULL;

    list_for_each_entry(node, &client_list, client) {

        list_for_each_entry_safe(p_info, tmp_info, &node->visit, visit) {
            if (p_info->expire)
            {
                list_del(&p_info->visit);
                free(p_info);
                count++;
            }
        }
    }
}

void dump_client_visit_list(void)
{
    int count = 0;
    FILE *fp = fopen(OAF_VISIT_LIST_FILE, "w");
    if (!fp)
    {
        return;
    }

    fprintf(fp, "%-4s %-20s %-20s %-8s %-32s %-32s %-32s %-8s\n", "Id", "Mac Addr",
            "Ip Addr", "Appid", "First Time", "Latest Time", "Total Time(s)", "Expire");
    
    client_node_t *node = NULL;
    visit_info_t *p_info = NULL;
    list_for_each_entry(node, &client_list, client) {

        list_for_each_entry(p_info, &node->visit, visit) {
            char *first_time_str = format_time(p_info->first_time);
            char *latest_time_str = format_time(p_info->latest_time);
            int total_time = p_info->latest_time - p_info->first_time;
            fprintf(fp, "%-4d %-20s %-20s %-8d %-32s %-32s %-32d %-4d\n",
                    count, node->mac, node->ip, p_info->appid, first_time_str,
                    latest_time_str, total_time, p_info->expire);
            if (first_time_str)
                free(first_time_str);
            if (latest_time_str)
                free(latest_time_str);
            count++;
            if (count > 50)
                goto EXIT;
        }
    }
EXIT:
    fclose(fp);
}


typedef struct app_hour_stat {
    int appid;
    unsigned long long total_time;
} app_hour_stat_t;


static int compare_app_stat(const void *a, const void *b) {
    app_hour_stat_t *pa = (app_hour_stat_t *)a;
    app_hour_stat_t *pb = (app_hour_stat_t *)b;
    if (pa->total_time > pb->total_time)
        return -1;
    if (pa->total_time < pb->total_time)
        return 1;
    return 0;
}


int get_hour_from_timestamp(u_int32_t timestamp) {
    time_t t = (time_t)timestamp;
    struct tm *tm_info = localtime(&t);
    if (!tm_info)
        return -1;
    return tm_info->tm_hour;
}


static int is_same_day(u_int32_t timestamp1, u_int32_t timestamp2) {
    time_t t1 = (time_t)timestamp1;
    time_t t2 = (time_t)timestamp2;
    struct tm *tm1 = localtime(&t1);
    struct tm *tm2 = localtime(&t2);
    if (!tm1 || !tm2)
        return 0;
    return (tm1->tm_year == tm2->tm_year &&
            tm1->tm_mon == tm2->tm_mon &&
            tm1->tm_mday == tm2->tm_mday);
}


u_int32_t get_today_start_timestamp(void) {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    if (!tm_info)
        return 0;
    tm_info->tm_hour = 0;
    tm_info->tm_min = 0;
    tm_info->tm_sec = 0;
    return (u_int32_t)mktime(tm_info);
}


daily_hourly_stat_t *get_today_stat(client_node_t *client) {
	int i, j;
    if (!client)
        return NULL;
    
    u_int32_t today = get_today_start_timestamp();
    
    
    if (client->daily_stats.date == today && client->daily_stats.is_today == 1) {
        return &client->daily_stats;
    }
    
    
    if (client->daily_stats.date != 0 && client->daily_stats.date != today) {
        save_daily_stats_to_file(client, client->daily_stats.date);
    }
    
    
    client->daily_stats.date = today;
    client->daily_stats.is_today = 1;
    for (i = 0; i < HOURS_PER_DAY; i++) {
        for (j = 0; j < TOP_APP_PER_HOUR; j++) {
            client->daily_stats.hourly_top_apps[i][j] = -1;
        }
        
        client->daily_stats.hourly_traffic[i].up_bytes = 0;
        client->daily_stats.hourly_traffic[i].down_bytes = 0;
        client->daily_stats.hourly_online_time[i] = 0;
        client->daily_stats.hourly_active_time[i] = 0;
    }
    
    return &client->daily_stats;
}


daily_hourly_stat_t *load_history_stat_from_file(client_node_t *client, u_int32_t date) {
    if (!client)
        return NULL;
    
    
    
    return NULL;
}


void update_hourly_top_apps(client_node_t *client) {
    if (!client)
        return;

    
    daily_hourly_stat_t *today_stat = get_today_stat(client);
    if (!today_stat)
        return;

    int cur_time = get_timestamp();
    app_hour_stat_t hour_stats[HOURS_PER_DAY][MAX_APP_STAT_NUM];
    int hour_count[HOURS_PER_DAY] = {0};
    int i, j;

    
    for (i = 0; i < HOURS_PER_DAY; i++) {
        hour_count[i] = 0;
        for (j = 0; j < MAX_APP_STAT_NUM; j++) {
            hour_stats[i][j].appid = -1;
            hour_stats[i][j].total_time = 0;
        }
    }

    
    visit_info_t *p_info = NULL;
    list_for_each_entry(p_info, &client->online_visit, visit) {
        if (!is_same_day(p_info->first_time, cur_time))
            continue;

        int hour = get_hour_from_timestamp(p_info->first_time);
        if (hour < 0 || hour >= HOURS_PER_DAY)
            continue;

        unsigned long long visit_time = p_info->latest_time - p_info->first_time;
        if (visit_time == 0)
            visit_time = 1; 

        int found = 0;
        for (i = 0; i < hour_count[hour]; i++) {
            if (hour_stats[hour][i].appid == p_info->appid) {
                hour_stats[hour][i].total_time += visit_time;
                found = 1;
                break;
            }
        }

        if (!found && hour_count[hour] < MAX_APP_STAT_NUM) {
            hour_stats[hour][hour_count[hour]].appid = p_info->appid;
            hour_stats[hour][hour_count[hour]].total_time = visit_time;
            hour_count[hour]++;
        } else if (!found && hour_count[hour] >= MAX_APP_STAT_NUM) {
            int min_idx = 0;
            unsigned long long min_time = hour_stats[hour][0].total_time;
            for (i = 1; i < MAX_APP_STAT_NUM; i++) {
                if (hour_stats[hour][i].total_time < min_time) {
                    min_time = hour_stats[hour][i].total_time;
                    min_idx = i;
                }
            }
            if (visit_time > min_time) {
                hour_stats[hour][min_idx].appid = p_info->appid;
                hour_stats[hour][min_idx].total_time = visit_time;
            }
        }
    }

    list_for_each_entry(p_info, &client->visit, visit) {
        
        if (!is_same_day(p_info->first_time, cur_time))
            continue;

        int hour = get_hour_from_timestamp(p_info->first_time);
        if (hour < 0 || hour >= HOURS_PER_DAY)
            continue;

        
        unsigned long long visit_time = p_info->latest_time - p_info->first_time;
        if (visit_time == 0)
            visit_time = 1; 

        
        int found = 0;
        for (i = 0; i < hour_count[hour]; i++) {
            if (hour_stats[hour][i].appid == p_info->appid) {
                hour_stats[hour][i].total_time += visit_time;
                found = 1;
                break;
            }
        }

        
        if (!found && hour_count[hour] < MAX_APP_STAT_NUM) {
            hour_stats[hour][hour_count[hour]].appid = p_info->appid;
            hour_stats[hour][hour_count[hour]].total_time = visit_time;
            hour_count[hour]++;
        } else if (!found && hour_count[hour] >= MAX_APP_STAT_NUM) {
            
            int min_idx = 0;
            unsigned long long min_time = hour_stats[hour][0].total_time;
            for (i = 1; i < MAX_APP_STAT_NUM; i++) {
                if (hour_stats[hour][i].total_time < min_time) {
                    min_time = hour_stats[hour][i].total_time;
                    min_idx = i;
                }
            }
            if (visit_time > min_time) {
                hour_stats[hour][min_idx].appid = p_info->appid;
                hour_stats[hour][min_idx].total_time = visit_time;
            }
        }
    }

    
    for (i = 0; i < HOURS_PER_DAY; i++) {
        
        for (j = 0; j < TOP_APP_PER_HOUR; j++) {
            today_stat->hourly_top_apps[i][j] = -1;
        }

        if (hour_count[i] == 0)
            continue;

        
        qsort(hour_stats[i], hour_count[i], sizeof(app_hour_stat_t), compare_app_stat);

        
        int top_count = (hour_count[i] < TOP_APP_PER_HOUR) ? hour_count[i] : TOP_APP_PER_HOUR;
        for (j = 0; j < top_count; j++) {
            if (hour_stats[i][j].appid > 0 && hour_stats[i][j].total_time > 0) {
                today_stat->hourly_top_apps[i][j] = hour_stats[i][j].appid;
            }
        }
    }
}


void get_hourly_top_apps(client_node_t *client, int hour, int *appids, int max_count) {

	int i;
    if (!client || !appids || hour < 0 || hour >= HOURS_PER_DAY || max_count <= 0)
        return;

    daily_hourly_stat_t *today_stat = get_today_stat(client);
    if (!today_stat)
        return;

    int count = (max_count < TOP_APP_PER_HOUR) ? max_count : TOP_APP_PER_HOUR;
    for (i = 0; i < count; i++) {
        appids[i] = today_stat->hourly_top_apps[hour][i];
    }
    
    for (i = count; i < max_count; i++) {
        appids[i] = -1;
    }
}


void save_daily_stats_to_file(client_node_t *client, u_int32_t date) {
	int i;
	int hour;
    if (!client)
        return;
    if (!jmx_storage_guard_allow(get_client_data_base_dir(),
                                 JMX_STORAGE_WRITE_BULK, NULL))
        return;
    
    daily_hourly_stat_t *stat = &client->daily_stats;
    if (stat->date != date) {
        char date_str[32] = {0};
        char stat_date_str[32] = {0};
        get_date_string(date, date_str, sizeof(date_str));
        get_date_string(stat->date, stat_date_str, sizeof(stat_date_str));
        LOG_DEBUG("Date mismatch for client %s hourly stats: requested %s, but stat date is %s, skip saving\n", 
                 client->mac, date_str, stat_date_str);
        return;  
    }
    
    
    char stats_dir[512] = {0};
    char mac_dirname[64] = {0};
    mac_to_dirname(client->mac, mac_dirname, sizeof(mac_dirname));
    snprintf(stats_dir, sizeof(stats_dir), "%s/%s/stats", get_client_data_base_dir(), mac_dirname);
    
    if (ensure_dir_exists(stats_dir) != 0) {
        char date_str[32] = {0};
        get_date_string(date, date_str, sizeof(date_str));
        LOG_ERROR("Failed to create stats directory %s for client %s hourly stats (date: %s)\n", 
                  stats_dir, client->mac, date_str);
        return;
    }
    
    
    char date_str[32] = {0};
    get_date_string(date, date_str, sizeof(date_str));
    
    char file_path[512] = {0};
    snprintf(file_path, sizeof(file_path), "%s/hourly_%s.json", stats_dir, date_str);
    
    
    struct json_object *json_obj = json_object_new_object();
    json_object_object_add(json_obj, "date", json_object_new_int64(date));
    json_object_object_add(json_obj, "mac", json_object_new_string(client->mac));
    
    
    struct json_object *hourly_array = json_object_new_array();
    for (hour = 0; hour < HOURS_PER_DAY; hour++) {
        struct json_object *hour_obj = json_object_new_object();
        struct json_object *apps_array = json_object_new_array();
        
        json_object_object_add(hour_obj, "hour", json_object_new_int(hour));
        
        for (i = 0; i < TOP_APP_PER_HOUR; i++) {
            if (stat->hourly_top_apps[hour][i] > 0) {
                struct json_object *app_obj = json_object_new_object();
                json_object_object_add(app_obj, "appid", json_object_new_int(stat->hourly_top_apps[hour][i]));
                const char *app_name = get_app_name_by_id(stat->hourly_top_apps[hour][i]);
                if (app_name) {
                    json_object_object_add(app_obj, "name", json_object_new_string(app_name));
                }
                json_object_array_add(apps_array, app_obj);
            }
        }
        
        json_object_object_add(hour_obj, "apps", apps_array);
        
        
        struct json_object *traffic_obj = json_object_new_object();
        json_object_object_add(traffic_obj, "up_bytes", json_object_new_int64(stat->hourly_traffic[hour].up_bytes));
        json_object_object_add(traffic_obj, "down_bytes", json_object_new_int64(stat->hourly_traffic[hour].down_bytes));
        json_object_object_add(hour_obj, "traffic", traffic_obj);
        
        
        json_object_object_add(hour_obj, "online_time", json_object_new_int64(stat->hourly_online_time[hour]));
        json_object_object_add(hour_obj, "active_time", json_object_new_int64(stat->hourly_active_time[hour]));
        
        json_object_array_add(hourly_array, hour_obj);
    }
    
    json_object_object_add(json_obj, "hourly_stats", hourly_array);
    
    
    const char *json_string = json_object_to_json_string_ext(json_obj, JSON_C_TO_STRING_PRETTY);
    FILE *fp = fopen(file_path, "w");
    if (fp) {
        fprintf(fp, "%s\n", json_string);
        fclose(fp);
        char date_str[32] = {0};
        get_date_string(date, date_str, sizeof(date_str));
        LOG_DEBUG("Saved daily hourly stats for client %s (date: %s) to %s\n", 
                 client->mac, date_str, file_path);
    } else {
        LOG_ERROR("Failed to save daily stats to file: %s (errno: %d)\n", file_path, errno);
    }
    
    json_object_put(json_obj);
}


static u_int32_t get_today_start_timestamp_from_ts(u_int32_t timestamp) {
    time_t t = (time_t)timestamp;
    struct tm *tm_info = localtime(&t);
    if (!tm_info)
        return 0;
    
    struct tm tm_day_start = *tm_info;
    tm_day_start.tm_hour = 0;
    tm_day_start.tm_min = 0;
    tm_day_start.tm_sec = 0;
    
    return (u_int32_t)mktime(&tm_day_start);
}


void add_online_offline_record(client_node_t *client, int type, u_int32_t timestamp, unsigned long long duration) {
    if (!client)
        return;
    
    online_offline_record_t *record = (online_offline_record_t *)calloc(1, sizeof(online_offline_record_t));
    if (!record) {
        LOG_ERROR("Failed to allocate memory for online_offline_record\n");
        return;
    }
    
    record->type = type;
    record->timestamp = timestamp;
    record->duration = duration;
    

    list_add(&record->record, &client->online_offline_records);
    
    LOG_DEBUG("Added %s record for client %s at timestamp %u, duration: %llu seconds\n",
             type == 0 ? "online" : "offline", client->mac, timestamp, duration);
}


void save_online_offline_records_to_file(client_node_t *client, u_int32_t date) {
    if (!client)
        return;
    if (!jmx_storage_guard_allow(get_client_data_base_dir(),
                                 JMX_STORAGE_WRITE_BULK, NULL))
        return;
    
    
    char stats_dir[512] = {0};
    char mac_dirname[64] = {0};
    mac_to_dirname(client->mac, mac_dirname, sizeof(mac_dirname));
    snprintf(stats_dir, sizeof(stats_dir), "%s/%s/stats", get_client_data_base_dir(), mac_dirname);
    
    if (ensure_dir_exists(stats_dir) != 0) {
        char date_str[32] = {0};
        get_date_string(date, date_str, sizeof(date_str));
        LOG_ERROR("Failed to create stats directory %s for client %s online_offline records (date: %s)\n", 
                  stats_dir, client->mac, date_str);
        return;
    }
    
    
    char date_str[32] = {0};
    get_date_string(date, date_str, sizeof(date_str));
    
    char file_path[512] = {0};
    snprintf(file_path, sizeof(file_path), "%s/online_offline_%s.json", stats_dir, date_str);
    
    
    struct json_object *json_obj = json_object_new_object();
    json_object_object_add(json_obj, "date", json_object_new_int64(date));
    json_object_object_add(json_obj, "mac", json_object_new_string(client->mac));
    
    
    struct json_object *records_array = json_object_new_array();
    online_offline_record_t *record = NULL;
    u_int32_t date_end = date + SECONDS_PER_DAY - 1;
    
    
    list_for_each_entry(record, &client->online_offline_records, record) {
        
        if (record->timestamp >= date && record->timestamp <= date_end) {
            struct json_object *record_obj = json_object_new_object();
            json_object_object_add(record_obj, "type", json_object_new_int(record->type));
            json_object_object_add(record_obj, "timestamp", json_object_new_int64(record->timestamp));
            json_object_object_add(record_obj, "duration", json_object_new_int64(record->duration));
            json_object_array_add(records_array, record_obj);
        }
    }
    
    json_object_object_add(json_obj, "records", records_array);
    
    
    const char *json_string = json_object_to_json_string_ext(json_obj, JSON_C_TO_STRING_PRETTY);
    FILE *fp = fopen(file_path, "w");
    if (fp) {
        fprintf(fp, "%s\n", json_string);
        fclose(fp);
        char date_str[32] = {0};
        get_date_string(date, date_str, sizeof(date_str));
        LOG_DEBUG("Saved online_offline records for client %s (date: %s) to %s\n", 
                 client->mac, date_str, file_path);
    } else {
        LOG_ERROR("Failed to save online_offline records to file: %s (errno: %d)\n", file_path, errno);
    }
    
    json_object_put(json_obj);
}


void archive_and_save_online_offline_records(void) {
    client_node_t *client = NULL;
    u_int32_t today = get_today_start_timestamp();
    
    list_for_each_entry(client, &client_list, client) {
        
        online_offline_record_t *record = NULL;
        u_int32_t oldest_date = 0;
        
        
        list_for_each_entry(record, &client->online_offline_records, record) {
            u_int32_t record_date = get_today_start_timestamp_from_ts(record->timestamp);
            if (oldest_date == 0 || record_date < oldest_date) {
                oldest_date = record_date;
            }
        }
        
        
        if (oldest_date != 0 && oldest_date < today) {
            
            for (u_int32_t date = oldest_date; date < today; date += SECONDS_PER_DAY) {
                
                int has_records = 0;
                list_for_each_entry(record, &client->online_offline_records, record) {
                    u_int32_t record_date = get_today_start_timestamp_from_ts(record->timestamp);
                    if (record_date == date) {
                        has_records = 1;
                        break;
                    }
                }
                
                if (has_records) {
                    save_online_offline_records_to_file(client, date);
                }
            }
            
            
            struct list_head *pos, *n;
            list_for_each_safe(pos, n, &client->online_offline_records) {
                record = list_entry(pos, online_offline_record_t, record);
                u_int32_t record_date = get_today_start_timestamp_from_ts(record->timestamp);
                if (record_date < today) {
                    list_del(pos);
                    free(record);
                }
            }
        }
    }
}


void save_global_traffic_stats_to_file(u_int32_t date) {
    if (!jmx_storage_guard_allow(get_client_data_base_dir(),
                                 JMX_STORAGE_WRITE_BULK, NULL))
        return;
    char date_str[32] = {0};
	int hour;
    get_date_string(date, date_str, sizeof(date_str));
    
    
    char global_stats_dir[512] = {0};
    snprintf(global_stats_dir, sizeof(global_stats_dir), "%s/global/stats", get_client_data_base_dir());
    
    if (ensure_dir_exists(global_stats_dir) != 0) {
        LOG_ERROR("Failed to create global stats directory %s for traffic stats (date: %s)\n", 
                  global_stats_dir, date_str);
        return;
    }
    
    
    char file_path[512] = {0};
    snprintf(file_path, sizeof(file_path), "%s/traffic_%s.json", global_stats_dir, date_str);
    
    
    struct json_object *json_obj = json_object_new_object();
    json_object_object_add(json_obj, "date", json_object_new_int64(date));
    
    
    struct json_object *hourly_array = json_object_new_array();
    for (hour = 0; hour < HOURS_PER_DAY; hour++) {
        struct json_object *hour_obj = json_object_new_object();
        
        json_object_object_add(hour_obj, "hour", json_object_new_int(hour));
        
        
        struct json_object *traffic_obj = json_object_new_object();
        json_object_object_add(traffic_obj, "up_bytes", json_object_new_int64(g_global_hourly_traffic[hour].up_bytes));
        json_object_object_add(traffic_obj, "down_bytes", json_object_new_int64(g_global_hourly_traffic[hour].down_bytes));
        json_object_object_add(hour_obj, "traffic", traffic_obj);
        
        json_object_array_add(hourly_array, hour_obj);
    }
    
    json_object_object_add(json_obj, "hourly_traffic", hourly_array);
    
    
    const char *json_string = json_object_to_json_string_ext(json_obj, JSON_C_TO_STRING_PRETTY);
    FILE *fp = fopen(file_path, "w");
    if (fp) {
        fprintf(fp, "%s\n", json_string);
        fclose(fp);
        LOG_DEBUG("Saved global traffic stats (date: %s) to %s\n", date_str, file_path);
    } else {
        LOG_ERROR("Failed to save global traffic stats to file: %s (errno: %d)\n", file_path, errno);
    }
    
    json_object_put(json_obj);
}



void check_and_archive_all_clients(void) {
	int i, j;
    client_node_t *node = NULL;
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    if (!tm_info){
        LOG_ERROR("Failed to get local time\n");
        return;
    }
    
    u_int32_t today = get_today_start_timestamp();
    
    u_int32_t yesterday = today - SECONDS_PER_DAY;
    
    char yesterday_str[32] = {0};
    char today_str[32] = {0};
    get_date_string(yesterday, yesterday_str, sizeof(yesterday_str));
    get_date_string(today, today_str, sizeof(today_str));
    
    LOG_DEBUG("Date changed: %s -> %s, starting archive process...\n", yesterday_str, today_str);
    
    int client_count = 0;
    list_for_each_entry(node, &client_list, client) {
        client_count++;
        LOG_DEBUG("archiving client %s\n", node->mac);

        visit_info_t *p_info = NULL, *tmp_info = NULL;
        list_for_each_entry_safe(p_info, tmp_info, &node->online_visit, visit) {

            int total_time = p_info->latest_time - p_info->first_time;
            if (total_time < g_app_valid_time) {
                LOG_DEBUG("Discard visit record on date change (too short): mac=%s, appid=%d, duration=%ds < %ds\n", 
                          node->mac, p_info->appid, total_time, g_app_valid_time);
                list_del(&p_info->visit);
                free(p_info);  // 直接删除，不加入visit列表
            } else {
                p_info->expire = 0;


                list_move(&p_info->visit, &node->visit);
            }
        }
        
        save_client_visit_data_to_file(node, yesterday);
        
        
        if (node->daily_stats.date == yesterday) {
            save_daily_stats_to_file(node, yesterday);
        }
        if (node->daily_top_apps_stats.date == yesterday) {
            save_daily_top_apps_stats_to_file(node, yesterday);
        }
        
        
        u_int32_t date_end = yesterday + SECONDS_PER_DAY - 1;
        
        list_for_each_entry_safe(p_info, tmp_info, &node->visit, visit) {
            if (p_info->first_time >= yesterday && p_info->first_time <= date_end) {
                list_del(&p_info->visit);
                free(p_info);
            }
        }
        
        
        visit_stat_t *stat_node = NULL, *tmp_stat_node = NULL;
        list_for_each_entry_safe(stat_node, tmp_stat_node, &node->stat_list, list) {
            list_del(&stat_node->list);
            free(stat_node);
        }
        
        
        node->daily_stats.date = today;
        node->daily_stats.is_today = 1;
        for (i = 0; i < HOURS_PER_DAY; i++) {
            for (j = 0; j < TOP_APP_PER_HOUR; j++) {
                node->daily_stats.hourly_top_apps[i][j] = -1;
            }
            
            node->daily_stats.hourly_traffic[i].up_bytes = 0;
            node->daily_stats.hourly_traffic[i].down_bytes = 0;
            node->daily_stats.hourly_online_time[i] = 0;
            node->daily_stats.hourly_active_time[i] = 0;
        }
        
        node->daily_top_apps_stats.date = today;
        node->daily_top_apps_stats.is_today = 1;
        node->daily_top_apps_stats.count = 0;
        for (i = 0; i < MAX_TOP_APPS_PER_DAY; i++) {
            node->daily_top_apps_stats.apps[i].appid = -1;
            node->daily_top_apps_stats.apps[i].total_time = 0;
        }
    }
    
    
    today = get_today_start_timestamp();
    if (g_daily_stat_date != today) {
        memset(g_daily_type_stats, 0, sizeof(g_daily_type_stats));
        g_daily_stat_date = today;
        LOG_DEBUG("Reset global daily type stats for new day\n");
    }
    
    
    if (g_global_traffic_date != 0 && g_global_traffic_date != today) {
        save_global_traffic_stats_to_file(g_global_traffic_date);
    }
    
    
    if (g_global_traffic_date != today) {
        memset(g_global_hourly_traffic, 0, sizeof(g_global_hourly_traffic));
        g_global_traffic_date = today;
        LOG_DEBUG("Reset global traffic stats for new day\n");
    }
    
    
    global_app_type_record_t *record = NULL, *tmp_record = NULL;
    list_for_each_entry_safe(record, tmp_record, &global_hourly_records, list) {
        list_del(&record->list);
        free(record);
    }
    LOG_DEBUG("Reset global hourly type stats for new day\n");
    
    LOG_DEBUG("Archive completed: processed %d clients for date %s\n", client_count, yesterday_str);
    
    
    cleanup_old_record_files();
}


typedef struct app_time_stat {
    int appid;
    unsigned long long total_time;
} app_time_stat_t;


static int compare_app_time_stat(const void *a, const void *b) {
    app_time_stat_t *pa = (app_time_stat_t *)a;
    app_time_stat_t *pb = (app_time_stat_t *)b;
    if (pa->total_time > pb->total_time)
        return -1;
    if (pa->total_time < pb->total_time)
        return 1;
    return 0;
}


daily_top_apps_stat_t *get_today_top_apps_stat(client_node_t *client) {
	int i;
    if (!client)
        return NULL;
    
    u_int32_t today = get_today_start_timestamp();
    
    
    if (client->daily_top_apps_stats.date == today && client->daily_top_apps_stats.is_today == 1) {
        return &client->daily_top_apps_stats;
    }
    
    
    if (client->daily_top_apps_stats.date != 0 && client->daily_top_apps_stats.date != today) {
        save_daily_top_apps_stats_to_file(client, client->daily_top_apps_stats.date);
    }
    
    
    client->daily_top_apps_stats.date = today;
    client->daily_top_apps_stats.is_today = 1;
    client->daily_top_apps_stats.count = 0;
    for (i = 0; i < MAX_TOP_APPS_PER_DAY; i++) {
        client->daily_top_apps_stats.apps[i].appid = -1;
        client->daily_top_apps_stats.apps[i].total_time = 0;
    }
    
    return &client->daily_top_apps_stats;
}


daily_top_apps_stat_t *load_history_top_apps_stat_from_file(client_node_t *client, u_int32_t date) {
    if (!client)
        return NULL;
    
    
    
    return NULL;
}


void update_daily_top_apps(client_node_t *client) {
    if (!client)
        return;

    
    daily_top_apps_stat_t *today_stat = get_today_top_apps_stat(client);
    if (!today_stat)
        return;

    int cur_time = get_timestamp();
    app_time_stat_t app_stats[MAX_APP_STAT_NUM];
    int app_count = 0;
    int i;

    
    for (i = 0; i < MAX_APP_STAT_NUM; i++) {
        app_stats[i].appid = -1;
        app_stats[i].total_time = 0;
    }

    
    visit_info_t *p_info = NULL;
    list_for_each_entry(p_info, &client->visit, visit) {
        
        if (!is_same_day(p_info->first_time, cur_time))
            continue;

        
        unsigned long long visit_time = p_info->latest_time - p_info->first_time;
        if (visit_time == 0)
            visit_time = 1; 

        
        int found = 0;
        for (i = 0; i < app_count; i++) {
            if (app_stats[i].appid == p_info->appid) {
                app_stats[i].total_time += visit_time;
                found = 1;
                break;
            }
        }

        
        if (!found && app_count < MAX_APP_STAT_NUM) {
            app_stats[app_count].appid = p_info->appid;
            app_stats[app_count].total_time = visit_time;
            app_count++;
        } else if (!found && app_count >= MAX_APP_STAT_NUM) {
            
            int min_idx = 0;
            unsigned long long min_time = app_stats[0].total_time;
            for (i = 1; i < MAX_APP_STAT_NUM; i++) {
                if (app_stats[i].total_time < min_time) {
                    min_time = app_stats[i].total_time;
                    min_idx = i;
                }
            }
            if (visit_time > min_time) {
                app_stats[min_idx].appid = p_info->appid;
                app_stats[min_idx].total_time = visit_time;
            }
        }
    }

    if (app_count == 0) {
        
        today_stat->count = 0;
        for (i = 0; i < MAX_TOP_APPS_PER_DAY; i++) {
            today_stat->apps[i].appid = -1;
            today_stat->apps[i].total_time = 0;
        }
        return;
    }

    
    qsort(app_stats, app_count, sizeof(app_time_stat_t), compare_app_time_stat);

    
    int top_count = (app_count < MAX_TOP_APPS_PER_DAY) ? app_count : MAX_TOP_APPS_PER_DAY;
    today_stat->count = 0;
    
    for (i = 0; i < top_count; i++) {
        if (app_stats[i].appid > 0 && app_stats[i].total_time > 0) {
            today_stat->apps[today_stat->count].appid = app_stats[i].appid;
            today_stat->apps[today_stat->count].total_time = app_stats[i].total_time;
            today_stat->count++;
        }
    }
    
    
    for (i = today_stat->count; i < MAX_TOP_APPS_PER_DAY; i++) {
        today_stat->apps[i].appid = -1;
        today_stat->apps[i].total_time = 0;
    }
}


void save_daily_top_apps_stats_to_file(client_node_t *client, u_int32_t date) {
	int i;
    if (!client)
        return;
    if (!jmx_storage_guard_allow(get_client_data_base_dir(),
                                 JMX_STORAGE_WRITE_BULK, NULL))
        return;
    
    daily_top_apps_stat_t *stat = &client->daily_top_apps_stats;
    if (stat->date != date) {
        char date_str[32] = {0};
        char stat_date_str[32] = {0};
        get_date_string(date, date_str, sizeof(date_str));
        get_date_string(stat->date, stat_date_str, sizeof(stat_date_str));
        LOG_DEBUG("Date mismatch for client %s: requested %s, but stat date is %s, skip saving\n", 
                 client->mac, date_str, stat_date_str);
        return;  
    }
    
    
    char stats_dir[512] = {0};
    char mac_dirname[64] = {0};
    mac_to_dirname(client->mac, mac_dirname, sizeof(mac_dirname));
    snprintf(stats_dir, sizeof(stats_dir), "%s/%s/stats", get_client_data_base_dir(), mac_dirname);
    
    if (ensure_dir_exists(stats_dir) != 0) {
        char date_str[32] = {0};
        get_date_string(date, date_str, sizeof(date_str));
        LOG_ERROR("Failed to create stats directory %s for client %s top apps (date: %s)\n", 
                  stats_dir, client->mac, date_str);
        return;
    }
    
    
    char date_str[32] = {0};
    get_date_string(date, date_str, sizeof(date_str));
    
    char file_path[512] = {0};
    snprintf(file_path, sizeof(file_path), "%s/top_apps_%s.json", stats_dir, date_str);
    
    
    struct json_object *json_obj = json_object_new_object();
    json_object_object_add(json_obj, "date", json_object_new_int64(date));
    json_object_object_add(json_obj, "mac", json_object_new_string(client->mac));
    json_object_object_add(json_obj, "count", json_object_new_int(stat->count));
    
    
    struct json_object *apps_array = json_object_new_array();
    for (i = 0; i < stat->count; i++) {
        struct json_object *app_obj = json_object_new_object();
        json_object_object_add(app_obj, "appid", json_object_new_int(stat->apps[i].appid));
        json_object_object_add(app_obj, "total_time", json_object_new_int64(stat->apps[i].total_time));
        const char *app_name = get_app_name_by_id(stat->apps[i].appid);
        if (app_name) {
            json_object_object_add(app_obj, "name", json_object_new_string(app_name));
        }
        json_object_array_add(apps_array, app_obj);
    }
    
    json_object_object_add(json_obj, "apps", apps_array);
    
    
    const char *json_string = json_object_to_json_string_ext(json_obj, JSON_C_TO_STRING_PRETTY);
    FILE *fp = fopen(file_path, "w");
    if (fp) {
        fprintf(fp, "%s\n", json_string);
        fclose(fp);
        char date_str[32] = {0};
        get_date_string(date, date_str, sizeof(date_str));
        LOG_DEBUG("Saved daily top apps stats for client %s (date: %s, count: %d) to %s\n", 
                 client->mac, date_str, stat->count, file_path);
    } else {
        LOG_ERROR("Failed to save daily top apps stats to file: %s (errno: %d)\n", file_path, errno);
    }
    
    json_object_put(json_obj);
}


static void mac_to_dirname(const char *mac, char *dirname, size_t len) {
	int i;
    if (!mac || !dirname || len == 0)
        return;
    
    strncpy(dirname, mac, len - 1);
    dirname[len - 1] = '\0';
    
    
    for (i = 0; dirname[i] != '\0'; i++) {
        if (dirname[i] == ':') {
            dirname[i] = '_';
        }
    }
}


static int ensure_dir_exists(const char *path) {
    char cmd[512] = {0};
    snprintf(cmd, sizeof(cmd), "mkdir -p %s", path);
    system(cmd);
    
    return 0;
}


static void get_date_string(u_int32_t timestamp, char *date_str, size_t len) {
    if (!date_str || len == 0)
        return;
    
    time_t t = (time_t)timestamp;
    struct tm *tm_info = localtime(&t);
    if (!tm_info) {
        date_str[0] = '\0';
        return;
    }
    
    strftime(date_str, len, "%Y-%m-%d", tm_info);
}


static void format_time_string(u_int32_t timestamp, char *time_str, size_t len) {
    if (!time_str || len == 0)
        return;
    
    time_t t = (time_t)timestamp;
    struct tm *tm_info = localtime(&t);
    if (!tm_info) {
        time_str[0] = '\0';
        return;
    }
    
    strftime(time_str, len, "%Y-%m-%d %H:%M:%S", tm_info);
}


void save_client_visit_data_to_file(client_node_t *client, u_int32_t date) {
    if (!client)
        return;
    if (!jmx_storage_guard_allow(get_client_data_base_dir(),
                                 JMX_STORAGE_WRITE_BULK, NULL))
        return;
    LOG_DEBUG("begin save_client_visit_data_to_file: %s, date: %u\n", client->mac, date);
    
    int visit_count = 0;
    visit_info_t *p_info = NULL;
    u_int32_t date_end = date + SECONDS_PER_DAY - 1;  
    
    list_for_each_entry(p_info, &client->visit, visit) {
        
        if (p_info->first_time >= date && p_info->first_time <= date_end) {
            visit_count++;
        }
    }
    
    
    if (visit_count == 0) {
        char date_str[32] = {0};
        get_date_string(date, date_str, sizeof(date_str));
        LOG_DEBUG("No visit records for client %s on date %s, skip saving\n", client->mac, date_str);
        return;
    }
    
    
    if (ensure_dir_exists(get_client_data_base_dir()) != 0) {
        LOG_ERROR("Failed to create base directory: %s\n", get_client_data_base_dir());
        return;
    }
    
    
    char visits_dir[512] = {0};
    char mac_dirname[64] = {0};
    mac_to_dirname(client->mac, mac_dirname, sizeof(mac_dirname));
    snprintf(visits_dir, sizeof(visits_dir), "%s/%s/visits", get_client_data_base_dir(), mac_dirname);
    
    if (ensure_dir_exists(visits_dir) != 0) {
        LOG_ERROR("Failed to create visits directory: %s\n", visits_dir);
        return;
    }
    
    
    char date_str[32] = {0};
    get_date_string(date, date_str, sizeof(date_str));
    
    char file_path[512] = {0};
    snprintf(file_path, sizeof(file_path), "%s/%s.txt", visits_dir, date_str);
    
    
    FILE *fp = fopen(file_path, "w");
    if (!fp) {
        char date_str_tmp[32] = {0};
        get_date_string(date, date_str_tmp, sizeof(date_str_tmp));
        LOG_ERROR("Failed to open file for writing: %s (client: %s, date: %s, errno: %d)\n", 
                  file_path, client->mac, date_str_tmp, errno);
        return;
    }
    
    
    fprintf(fp, "# Client Information\n");
    fprintf(fp, "MAC: %s\n", client->mac);
    fprintf(fp, "IP: %s\n", client->ip[0] ? client->ip : "N/A");
    fprintf(fp, "Hostname: %s\n", client->hostname[0] ? client->hostname : "N/A");
    fprintf(fp, "Nickname: %s\n", client->nickname[0] ? client->nickname : "N/A");
    fprintf(fp, "Record Count: %d\n", visit_count);
    fprintf(fp, "Date: %s\n", date_str);
    fprintf(fp, "\n");
    
    fprintf(fp, "# Visit Records\n");
    fprintf(fp, "%-32s %-20s %-20s %-12s %-8s\n", 
            "App Name", "Start Time", "End Time", "Duration(s)", "Action");
    fprintf(fp, "%-32s %-20s %-20s %-12s %-8s\n", 
            "--------------------------------", "--------------------", "--------------------", "------------", "--------");
            LOG_DEBUG("write client information to file: %s\n", file_path);

    
    list_for_each_entry(p_info, &client->visit, visit) {
        
        if (p_info->first_time < date || p_info->first_time > date_end) {
            LOG_DEBUG("skip visit record: %u, %u\n", p_info->first_time, date_end);
            continue;
        }
        
        char start_time_str[32] = {0};
        char end_time_str[32] = {0};
        format_time_string(p_info->first_time, start_time_str, sizeof(start_time_str));
        format_time_string(p_info->latest_time, end_time_str, sizeof(end_time_str));
        
        int duration = p_info->latest_time - p_info->first_time;
        if (duration == 0)
            duration = 1;
        
        
        const char *app_name = get_app_name_by_id(p_info->appid);
        if (!app_name)
            app_name = "unknown";
        
        fprintf(fp, "%-32s %-20s %-20s %-12d %-8d\n",
                app_name, start_time_str, end_time_str, duration, p_info->action);
    }
    LOG_DEBUG("write visit records to file: %s\n", file_path);
    
    fclose(fp);
    
    LOG_DEBUG("Saved visit data for client %s (date: %s, records: %d) to %s\n", 
             client->mac, date_str, visit_count, file_path);
}


static u_int32_t parse_date_string(const char *date_str) {
    if (!date_str)
        return 0;
    
    struct tm tm_info = {0};
    if (sscanf(date_str, "%d-%d-%d", &tm_info.tm_year, &tm_info.tm_mon, &tm_info.tm_mday) != 3)
        return 0;
    
    tm_info.tm_year -= 1900;  
    tm_info.tm_mon -= 1;       
    tm_info.tm_hour = 0;
    tm_info.tm_min = 0;
    tm_info.tm_sec = 0;
    
    return (u_int32_t)mktime(&tm_info);
}


static int extract_date_from_filename(const char *filename, char *date_str, size_t len) {
	int i;
    if (!filename || !date_str || len == 0)
        return -1;
    
    
    const char *prefixes[] = {"hourly_", "top_apps_", "traffic_", NULL};
    const char *start = filename;
    
    
    for (i = 0; prefixes[i] != NULL; i++) {
        size_t prefix_len = strlen(prefixes[i]);
        if (strncmp(filename, prefixes[i], prefix_len) == 0) {
            start = filename + prefix_len;
            break;
        }
    }
    
    
    int year, mon, mday;
    if (sscanf(start, "%d-%d-%d", &year, &mon, &mday) != 3)
        return -1;
    
    snprintf(date_str, len, "%04d-%02d-%02d", year, mon, mday);
    return 0;
}


static void cleanup_old_record_files(void) {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    if (!tm_info) {
        LOG_ERROR("Failed to get local time for cleanup\n");
        return;
    }
    
    
    u_int32_t expire_timestamp = (u_int32_t)now - (MAX_RECORD_DAY * SECONDS_PER_DAY);
    
    DIR *base_dir = opendir(get_client_data_base_dir());
    if (!base_dir) {
        LOG_DEBUG("Base directory %s does not exist, skip cleanup\n", get_client_data_base_dir());
        return;
    }
    
    struct dirent *client_entry;
    int deleted_count = 0;
    
    
    while ((client_entry = readdir(base_dir)) != NULL) {
        if (client_entry->d_name[0] == '.')
            continue;  
        
        char client_dir[512] = {0};
        snprintf(client_dir, sizeof(client_dir), "%s/%s", get_client_data_base_dir(), client_entry->d_name);
        
        struct stat st;
        if (stat(client_dir, &st) != 0 || !S_ISDIR(st.st_mode))
            continue;  
        
        
        char visits_dir[512] = {0};
        snprintf(visits_dir, sizeof(visits_dir), "%s/visits", client_dir);
        
        DIR *visits_dp = opendir(visits_dir);
        if (visits_dp) {
            struct dirent *file_entry;
            while ((file_entry = readdir(visits_dp)) != NULL) {
                if (file_entry->d_name[0] == '.')
                    continue;
                
                char date_str[32] = {0};
                if (extract_date_from_filename(file_entry->d_name, date_str, sizeof(date_str)) == 0) {
                    u_int32_t file_date = parse_date_string(date_str);
                    if (file_date > 0 && file_date < expire_timestamp) {
                        char file_path[512] = {0};
                        snprintf(file_path, sizeof(file_path), "%s/%s", visits_dir, file_entry->d_name);
                        if (unlink(file_path) == 0) {
                            deleted_count++;
                            LOG_DEBUG("Deleted expired visit file: %s (date: %s)\n", file_path, date_str);
                        } else {
                            LOG_ERROR("Failed to delete file: %s (errno: %d)\n", file_path, errno);
                        }
                    }
                }
            }
            closedir(visits_dp);
        }
        
        
        char stats_dir[512] = {0};
        snprintf(stats_dir, sizeof(stats_dir), "%s/stats", client_dir);
        
        DIR *stats_dp = opendir(stats_dir);
        if (stats_dp) {
            struct dirent *file_entry;
            while ((file_entry = readdir(stats_dp)) != NULL) {
                if (file_entry->d_name[0] == '.')
                    continue;
                
                char date_str[32] = {0};
                if (extract_date_from_filename(file_entry->d_name, date_str, sizeof(date_str)) == 0) {
                    u_int32_t file_date = parse_date_string(date_str);
                    if (file_date > 0 && file_date < expire_timestamp) {
                        char file_path[512] = {0};
                        snprintf(file_path, sizeof(file_path), "%s/%s", stats_dir, file_entry->d_name);
                        if (unlink(file_path) == 0) {
                            deleted_count++;
                            LOG_DEBUG("Deleted expired stats file: %s (date: %s)\n", file_path, date_str);
                        } else {
                            LOG_ERROR("Failed to delete file: %s (errno: %d)\n", file_path, errno);
                        }
                    }
                }
            }
            closedir(stats_dp);
        }
    }
    
    closedir(base_dir);
    
    
    char global_stats_dir[512] = {0};
    snprintf(global_stats_dir, sizeof(global_stats_dir), "%s/global/stats", get_client_data_base_dir());
    
    DIR *global_stats_dp = opendir(global_stats_dir);
    if (global_stats_dp) {
        struct dirent *file_entry;
        while ((file_entry = readdir(global_stats_dp)) != NULL) {
            if (file_entry->d_name[0] == '.')
                continue;
            
            char date_str[32] = {0};
            if (extract_date_from_filename(file_entry->d_name, date_str, sizeof(date_str)) == 0) {
                u_int32_t file_date = parse_date_string(date_str);
                if (file_date > 0 && file_date < expire_timestamp) {
                    char file_path[512] = {0};
                    snprintf(file_path, sizeof(file_path), "%s/%s", global_stats_dir, file_entry->d_name);
                    if (unlink(file_path) == 0) {
                        deleted_count++;
                        LOG_DEBUG("Deleted expired global traffic stats file: %s (date: %s)\n", file_path, date_str);
                    } else {
                        LOG_ERROR("Failed to delete file: %s (errno: %d)\n", file_path, errno);
                    }
                }
            }
        }
        closedir(global_stats_dp);
    }
    
    if (deleted_count > 0) {
        LOG_DEBUG("Cleanup completed: deleted %d expired record files (older than %d days)\n", 
                 deleted_count, MAX_RECORD_DAY);
    }
}


void get_global_traffic_stats(traffic_stat_t *traffic_array) {
    if (!traffic_array)
        return;
    
    
    u_int32_t today = get_today_start_timestamp();
    if (g_global_traffic_date != today) {
        memset(g_global_hourly_traffic, 0, sizeof(g_global_hourly_traffic));
        g_global_traffic_date = today;
    }
    
    
    memcpy(traffic_array, g_global_hourly_traffic, sizeof(g_global_hourly_traffic));
}






void delete_client_record_files(const char *mac, const char *start_date, const char *end_date, const char *delete_type) {
    u_int32_t start_timestamp = 0;
    u_int32_t end_timestamp = UINT32_MAX;
    
    
    if (start_date && strlen(start_date) > 0) {
        
        if (strchr(start_date, '-')) {
            start_timestamp = parse_date_string(start_date);
        } else {
            start_timestamp = (u_int32_t)atoi(start_date);
        }
    }
    
    
    if (end_date && strlen(end_date) > 0) {
        if (strchr(end_date, '-')) {
            u_int32_t end_date_ts = parse_date_string(end_date);
            
            end_timestamp = end_date_ts + SECONDS_PER_DAY - 1;
        } else {
            end_timestamp = (u_int32_t)atoi(end_date);
        }
    }
    
    
    int delete_visits = 1;
    int delete_stats = 1;
    if (delete_type && strlen(delete_type) > 0) {
        if (strcmp(delete_type, "visits") == 0) {
            delete_visits = 1;
            delete_stats = 0;
        } else if (strcmp(delete_type, "stats") == 0) {
            delete_visits = 0;
            delete_stats = 1;
        } else if (strcmp(delete_type, "all") == 0) {
            delete_visits = 1;
            delete_stats = 1;
        }
    }
    
    char mac_dirname[64] = {0};
    int specific_mac = 0;
    if (mac && strlen(mac) > 0) {
        mac_to_dirname(mac, mac_dirname, sizeof(mac_dirname));
        specific_mac = 1;
    }
    
    DIR *base_dir = opendir(get_client_data_base_dir());
    if (!base_dir) {
        LOG_DEBUG("Base directory %s does not exist, nothing to delete\n", get_client_data_base_dir());
        return;
    }
    
    struct dirent *client_entry;
    int deleted_count = 0;
    
    
    while ((client_entry = readdir(base_dir)) != NULL) {
        if (client_entry->d_name[0] == '.')
            continue;  
        
        
        if (specific_mac && strcmp(client_entry->d_name, mac_dirname) != 0)
            continue;
        
        char client_dir[512] = {0};
        snprintf(client_dir, sizeof(client_dir), "%s/%s", get_client_data_base_dir(), client_entry->d_name);
        
        struct stat st;
        if (stat(client_dir, &st) != 0 || !S_ISDIR(st.st_mode))
            continue;  
        
        
        if (delete_visits) {
            char visits_dir[512] = {0};
            snprintf(visits_dir, sizeof(visits_dir), "%s/visits", client_dir);
            
            DIR *visits_dp = opendir(visits_dir);
            if (visits_dp) {
                struct dirent *file_entry;
                while ((file_entry = readdir(visits_dp)) != NULL) {
                    if (file_entry->d_name[0] == '.')
                        continue;
                    
                    char date_str[32] = {0};
                    if (extract_date_from_filename(file_entry->d_name, date_str, sizeof(date_str)) == 0) {
                        u_int32_t file_date = parse_date_string(date_str);
                        if (file_date > 0 && file_date >= start_timestamp && file_date <= end_timestamp) {
                            char file_path[512] = {0};
                            snprintf(file_path, sizeof(file_path), "%s/%s", visits_dir, file_entry->d_name);
                            if (unlink(file_path) == 0) {
                                deleted_count++;
                                LOG_DEBUG("Deleted visit file: %s (date: %s)\n", file_path, date_str);
                            } else {
                                LOG_ERROR("Failed to delete file: %s (errno: %d)\n", file_path, errno);
                            }
                        }
                    }
                }
                closedir(visits_dp);
            }
        }
        
        
        if (delete_stats) {
            char stats_dir[512] = {0};
            snprintf(stats_dir, sizeof(stats_dir), "%s/stats", client_dir);
            
            DIR *stats_dp = opendir(stats_dir);
            if (stats_dp) {
                struct dirent *file_entry;
                while ((file_entry = readdir(stats_dp)) != NULL) {
                    if (file_entry->d_name[0] == '.')
                        continue;
                    
                    char date_str[32] = {0};
                    if (extract_date_from_filename(file_entry->d_name, date_str, sizeof(date_str)) == 0) {
                        u_int32_t file_date = parse_date_string(date_str);
                        if (file_date > 0 && file_date >= start_timestamp && file_date <= end_timestamp) {
                            char file_path[768] = {0};  
                            int path_len = snprintf(file_path, sizeof(file_path), "%s/%s", stats_dir, file_entry->d_name);
                            if (path_len >= 0 && path_len < sizeof(file_path)) {
                                if (unlink(file_path) == 0) {
                                    deleted_count++;
                                    LOG_DEBUG("Deleted stats file: %s (date: %s)\n", file_path, date_str);
                                } else {
                                    LOG_ERROR("Failed to delete file: %s (errno: %d)\n", file_path, errno);
                                }
                            } else {
                                LOG_ERROR("File path too long: %s/%s\n", stats_dir, file_entry->d_name);
                            }
                        }
                    }
                }
                closedir(stats_dp);
            }
        }
    }
    
    closedir(base_dir);
    
    LOG_DEBUG("Delete completed: deleted %d record files\n", deleted_count);
}


void update_global_app_type_stats(int appid, unsigned long long time_delta) {
    if (appid <= 0 || time_delta == 0)
        return;
    
    int app_type = appid / 1000;
    if (app_type <= 0 || app_type > MAX_APP_TYPE)
        return;
    
    int type_index = app_type - 1;  
    u_int32_t cur_time = get_timestamp();
    
    
    u_int32_t today = get_today_start_timestamp();
    if (g_daily_stat_date != today) {
        memset(g_daily_type_stats, 0, sizeof(g_daily_type_stats));
        g_daily_stat_date = today;
    }
    
    
    g_daily_type_stats[type_index] += time_delta;
    
    
    global_app_type_record_t *record = (global_app_type_record_t *)calloc(1, sizeof(global_app_type_record_t));
    if (record) {
        record->app_type = app_type;
        record->time_delta = time_delta;
        record->timestamp = cur_time;
        INIT_LIST_HEAD(&record->list);
        list_add_tail(&record->list, &global_hourly_records);
    }
}


void cleanup_expired_hourly_stats(void) {
    u_int32_t cur_time = get_timestamp();
    u_int32_t expire_time = cur_time - 3600;  
    
    global_app_type_record_t *record = NULL, *tmp_record = NULL;
    int cleared_count = 0;
    
    
    list_for_each_entry_safe(record, tmp_record, &global_hourly_records, list) {
        if (record->timestamp < expire_time) {
            
            list_del(&record->list);
            free(record);
            cleared_count++;
        } else {
            
            break;
        }
    }
    
    if (cleared_count > 0) {
        LOG_DEBUG("Cleared %d expired hourly records\n", cleared_count);
    }
}


void get_global_daily_app_type_stats(unsigned long long *type_time_array) {
    if (!type_time_array)
        return;
    
    
    u_int32_t today = get_today_start_timestamp();
    if (g_daily_stat_date != today) {
        memset(g_daily_type_stats, 0, sizeof(g_daily_type_stats));
        g_daily_stat_date = today;
    }
    
    
    memcpy(type_time_array, g_daily_type_stats, sizeof(g_daily_type_stats));
}


void get_global_hourly_app_type_stats(unsigned long long *type_time_array) {
    if (!type_time_array)
        return;
    
    
    cleanup_expired_hourly_stats();
    
    
    memset(type_time_array, 0, sizeof(unsigned long long) * MAX_APP_TYPE);
    
    
    u_int32_t cur_time = get_timestamp();
    u_int32_t expire_time = cur_time - 3600;  
    
    global_app_type_record_t *record = NULL;
    list_for_each_entry(record, &global_hourly_records, list) {
        if (record->timestamp >= expire_time) {
            int type_index = record->app_type - 1;
            if (type_index >= 0 && type_index < MAX_APP_TYPE) {
                type_time_array[type_index] += record->time_delta;
            }
        }
    }
}
