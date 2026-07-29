#include "proc_path.h"
// SPDX-License-Identifier: GPL-2.0-or-later
/* 
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>  
*/
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <libubox/uloop.h>
#include <libubox/utils.h>
#include <libubus.h>
#include "jmx_core_watchdog.h"
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <linux/netlink.h>
#include <linux/socket.h>
#include <sys/socket.h>
#include <json-c/json.h>
#include <sys/time.h>
#include <time.h>
#include <libubox/blobmsg_json.h>
#include <libubox/blobmsg.h>
#include "jmx_user.h"
#include "jmx_config.h"
#include <uci.h>
#include "jmx.h"
#include "jmx_db.h"
#include "jmx_utils.h"
#include "jmx_netconfig_db.h"

#define CLIENT_DATA_BASE_DIR_DEFAULT "/tmp/jmx/client_data"
#include "jmx_app_filter.h"
#include "jmx_mac_filter.h"
#include "jmx_network.h"
#include "jmx_system.h"
#include "jmx_audit.h"
#include "jmx_domain.h"
#include "jmx_hosttype.h"
#include "jmx_regex.h"
#include "jmx_route.h"
#include "jmx_dreamingwrt_api.h"
#include "jmx_signature_update.h"
#include "jmx_system_data_path.h"
#include <fcntl.h>
#include <unistd.h>
#include <libubox/list.h>

extern jmx_status_t g_jmx_status;
extern void reload_oaf_rule(void);


#define MAX_INTERFACE_TRAFFIC_POINTS 30
#define INTERFACE_TRAFFIC_INTERVAL 2  

typedef struct interface_traffic_node {
    struct list_head list;
    unsigned long long up_bytes;      
    unsigned long long down_bytes;    
    unsigned int up_rate;             
    unsigned int down_rate;           
    u_int32_t timestamp;              
} interface_traffic_node_t;


static LIST_HEAD(interface_traffic_list);
static int interface_traffic_count = 0;
static char g_interface_name[16] = {0};  
static unsigned long long last_up_bytes = 0;
static unsigned long long last_down_bytes = 0;
static u_int32_t last_traffic_time = 0;

struct ubus_context *ubus_ctx = NULL;
static struct blob_buf b;
static struct uloop_timeout jmx_ubus_reconnect_timer;
static struct uloop_timeout jmx_ubus_health_timer;
static const char *jmx_ubus_path_primary = "/var/run/ubus/ubus.sock";
static const char *jmx_ubus_path_fallback = "/var/run/ubus.sock";

static void jmx_ubus_connection_lost(struct ubus_context *ctx);

extern char *format_time(int timetamp);

void ubus_response_json(struct ubus_context *ctx, struct ubus_request_data *req, struct json_object *response){
    struct blob_buf b_buf = {};
    blob_buf_init(&b_buf, 0);
    blobmsg_add_object(&b_buf, response);
    ubus_send_reply(ctx, req, b_buf.head);
    blob_buf_free(&b_buf);
}

void reload_oaf_rule(){
    system("/usr/bin/oaf_rule reload");
}

static const char *lookup_signature_app(unsigned int app_id, char *name, size_t name_len,
                                        char *icon, size_t icon_len);

static const char *jmx_safe_app_name(int appid)
{
    const char *name = get_app_name_by_id(appid);
    if (name && name[0] != '\0')
        return name;

    {
        static char signature_name[128];

        if (lookup_signature_app((unsigned int)appid, signature_name,
                                 sizeof(signature_name), NULL, 0) != NULL &&
            signature_name[0] != '\0')
            return signature_name;
    }

    return "unknown";
}

static const char *jmx_safe_class_name(int type_index)
{
    const char *name;

    if (type_index < 0 || type_index >= MAX_APP_TYPE)
        return "unknown";

    if (!CLASS_NAME_TABLE)
        return "unknown";

    name = CLASS_NAME_TABLE[type_index];
    if (!name || name[0] == '\0')
        return "unknown";

    return name;
}

void get_hostname_by_mac(char *mac, char *hostname)
{
    if (!mac || !hostname)
        return;
    FILE *fp = fopen("/tmp/dhcp.leases", "r");
    if (!fp)
    {
        printf("open dhcp lease file....failed\n");
        return;
    }
    char line_buf[256] = {0};
    while (fgets(line_buf, sizeof(line_buf), fp))
    {
        char hostname_buf[MAX_HOSTNAME_SIZE] = {0};
        char mac_buf[32] = {0};
        if (sscanf(line_buf, "%*s %31s %*s %63s", mac_buf, hostname_buf) < 2)
            continue;
        if (0 == strcmp(mac, mac_buf))
        {
            snprintf(hostname, MAX_HOSTNAME_SIZE, "%s", hostname_buf);
        }
    }
    fclose(fp);
}

int compare_lt(const void *a, const void *b)
{
    struct json_object *obj_a = *(struct json_object **)a;
    struct json_object *obj_b = *(struct json_object **)b;
    struct json_object *lt_a = NULL, *lt_b = NULL;
    int lt_val_a = 0;
    int lt_val_b = 0;

    if (obj_a)
        json_object_object_get_ex(obj_a, "lt", &lt_a);
    if (obj_b)
        json_object_object_get_ex(obj_b, "lt", &lt_b);

    if (lt_a)
        lt_val_a = json_object_get_int(lt_a);
    if (lt_b)
        lt_val_b = json_object_get_int(lt_b);

    return lt_val_b - lt_val_a;
}


typedef struct {
    int app_id;
    unsigned long long total_time;
} app_stat_sort_t;


static int compare_app_stat_sort(const void *a, const void *b) {
    app_stat_sort_t *pa = (app_stat_sort_t *)a;
    app_stat_sort_t *pb = (app_stat_sort_t *)b;
    if (pa->total_time > pb->total_time)
        return -1;
    if (pa->total_time < pb->total_time)
        return 1;
    return 0;
}

void update_app_visit_time_list(const char *mac, struct app_visit_stat_info *visit_info)
{
	int i;
    client_node_t *node = find_client_node(mac);
    if (!node)
    {
        printf("not found mac:%s\n", mac);
        return;
    }
    
    
    app_stat_sort_t app_stats[MAX_APP_STAT_NUM * 2];  
    int app_count = 0;
    
    visit_stat_t *stat_node = NULL;
    list_for_each_entry(stat_node, &node->stat_list, list) {
        if (stat_node->total_time == 0)
            continue;
        
        
        int found = 0;
        for (i = 0; i < app_count; i++) {
            if (app_stats[i].app_id == stat_node->appid) {
                app_stats[i].total_time += stat_node->total_time;
                found = 1;
                break;
            }
        }
        
        
        if (!found) {
            if (app_count < MAX_APP_STAT_NUM * 2) {
                app_stats[app_count].app_id = stat_node->appid;
                app_stats[app_count].total_time = stat_node->total_time;
                app_count++;
            }
        }
    }
    
    
    if (app_count > 0) {
        qsort(app_stats, app_count, sizeof(app_stat_sort_t), compare_app_stat_sort);
        
        int top_count = (app_count < MAX_APP_STAT_NUM) ? app_count : MAX_APP_STAT_NUM;
        for (i = 0; i < top_count; i++) {
            visit_info->visit_list[i].app_id = app_stats[i].app_id;
            visit_info->visit_list[i].total_time = app_stats[i].total_time;
        }
        visit_info->num = top_count;
    } else {
        visit_info->num = 0;
    }
}

void update_app_class_visit_time_list(const char *mac, int *visit_time)
{
    client_node_t *node = find_client_node(mac);
    if (!node)
    {
        printf("not found mac:%s\n", mac);
        return;
    }
    
    
    visit_stat_t *stat_node = NULL;
    list_for_each_entry(stat_node, &node->stat_list, list) {
        if (stat_node->total_time == 0)
            continue;
        
        int type = stat_node->appid / 1000;
        if (type > 0 && type <= MAX_APP_TYPE) {
            visit_time[type - 1] += stat_node->total_time;
        }
    }
}

void ubus_get_dev_visit_time_info(char *mac, struct blob_buf *b)
{
    struct app_visit_stat_info info;
    memset((char *)&info, 0x0, sizeof(info));
    update_app_visit_time_list(mac, &info);
}

static int handle_debug(struct ubus_context *ctx, struct ubus_object *obj,
                            struct ubus_request_data *req, const char *method,
                            struct blob_attr *msg)
{
    blob_buf_init(&b, 0);
    char *msg_obj_str = blobmsg_format_json(msg, true);
    if (!msg_obj_str)
    {
        printf("format json failed\n");
        return 0;
    }

    struct json_object *req_obj = json_tokener_parse(msg_obj_str);
    struct json_object *debug_obj = json_object_object_get(req_obj, "debug");

    if (debug_obj)
    {
        current_log_level = json_object_get_int(debug_obj);
        LOG_WARN("debug level set to %d\n", current_log_level);
    }

    ubus_send_reply(ctx, req, b.head);
    return 0;
}



typedef struct app_visit_time_info
{
    int app_id;
    unsigned long long total_time;
} app_visit_time_info_t;

int visit_time_compare(const void *a, const void *b)
{
    app_visit_time_info_t *p1 = (app_visit_time_info_t *)a;
    app_visit_time_info_t *p2 = (app_visit_time_info_t *)b;
    return p1->total_time < p2->total_time ? 1 : -1;
}

#define MAX_STAT_APP_NUM 128
void update_top5_app(client_node_t *node, app_visit_time_info_t top5_app_list[])
{
	int i;
    int copied = 0;

    /*
     * Legacy get_all_users(flag=3) used to walk node->stat_list here.
     * The modern split collectors update client/runtime data from multiple
     * workers, while old LuCI can still poll this path.  A damaged or
     * concurrently-reset stat_list must not be able to crash dreamingwrt-core;
     * use the fixed-size daily_top_apps_stats snapshot instead and fall back to
     * the current visiting_app.  Returning a smaller/empty applist is better
     * than dropping the whole ubus object.
     */
    if (!node || !top5_app_list)
        return;

    if (node->daily_top_apps_stats.count > 0) {
        int n = node->daily_top_apps_stats.count;
        if (n > 5)
            n = 5;
        if (n > MAX_TOP_APPS_PER_DAY)
            n = MAX_TOP_APPS_PER_DAY;
        for (i = 0; i < n; i++) {
            int appid = node->daily_top_apps_stats.apps[i].appid;
            unsigned long long total_time = node->daily_top_apps_stats.apps[i].total_time;

            if (appid <= 0 || total_time == 0)
                continue;
            top5_app_list[copied].app_id = appid;
            top5_app_list[copied].total_time = total_time;
            copied++;
            if (copied >= 5)
                return;
        }
    }

    if (copied == 0 && node->visiting_app > 0) {
        top5_app_list[0].app_id = node->visiting_app;
        top5_app_list[0].total_time = 1;
    }
}

static int parse_signature_classes(struct json_object *class_list)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *categories = NULL;
    sqlite3_stmt *apps = NULL;
    int rc = -1;

    if (jmx_signature_db_open(&db) != 0)
        return -1;
    if (sqlite3_prepare_v2(db,
            "SELECT category_id,name FROM app_category ORDER BY sort_order,category_id",
            -1, &categories, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(db,
            "SELECT a.app_id,a.name,CASE WHEN ia.icon_file IS NULL OR ia.icon_file='' THEN 0 ELSE 1 END "
            "FROM app a LEFT JOIN app_icon ai ON ai.app_id=a.app_id "
            "LEFT JOIN icon_asset ia ON ia.icon_key=ai.icon_key "
            "WHERE a.enabled=1 AND a.category_id=?1 ORDER BY a.app_id",
            -1, &apps, NULL) != SQLITE_OK)
        goto done;
    while (sqlite3_step(categories) == SQLITE_ROW) {
        struct json_object *category = json_object_new_object();
        struct json_object *app_list = json_object_new_array();
        int category_id = sqlite3_column_int(categories, 0);
        const char *category_name = (const char *)sqlite3_column_text(categories, 1);

        json_object_object_add(category, "name",
                               json_object_new_string(category_name ? category_name : ""));
        sqlite3_bind_int(apps, 1, category_id);
        while (sqlite3_step(apps) == SQLITE_ROW) {
            char combined[256];
            int app_id = sqlite3_column_int(apps, 0);
            const char *app_name = (const char *)sqlite3_column_text(apps, 1);
            int with_icon = sqlite3_column_int(apps, 2);

            snprintf(combined, sizeof(combined), "%d,%s,%d", app_id,
                     app_name ? app_name : "", with_icon);
            json_object_array_add(app_list, json_object_new_string(combined));
        }
        if (sqlite3_reset(apps) != SQLITE_OK) {
            json_object_put(category);
            json_object_put(app_list);
            goto done;
        }
        sqlite3_clear_bindings(apps);
        json_object_object_add(category, "app_list", app_list);
        json_object_array_add(class_list, category);
    }
    rc = 0;

done:
    sqlite3_finalize(apps);
    sqlite3_finalize(categories);
    jmx_signature_db_close(db);
    return rc;
}

typedef struct all_users_info {
    int flag;
    struct json_object *users_array;
} all_users_info_t;

void all_users_callback(void *arg, client_node_t *client)
{
    int flag = 0;
    int i;
	int hour;
    all_users_info_t *au_info = (all_users_info_t *)arg;
    if (!au_info || !client) {
        LOG_ERROR("all_users_callback: arg or client is NULL\n");
        return;
    }
    
    flag = au_info->flag;
    struct json_object *users_array = au_info->users_array;
    if (!users_array) {
        LOG_ERROR("all_users_callback: users_array is NULL\n");
        return;
    }

    int current_count = json_object_array_length(users_array);
    if (current_count >= MAX_SUPPORT_DEV_NUM)
    {
        LOG_ERROR("all_users_callback: users_array length (%d) >= MAX_SUPPORT_DEV_NUM (%d), skipping\n", 
               current_count, MAX_SUPPORT_DEV_NUM);
        return;
    }

    LOG_DEBUG("all_users_callback: Processing client - mac=%s, online=%d, flag=%d, current_count=%d\n", 
           client->mac, client->online, flag, current_count);

    struct json_object *user_obj = json_object_new_object();
    if (!user_obj) {
        LOG_ERROR("all_users_callback: Failed to create user_obj for mac=%s\n", client->mac);
        return;
    }
    
    json_object_object_add(user_obj, "mac", json_object_new_string(client->mac));
    json_object_object_add(user_obj, "online", json_object_new_int(client->online));
    json_object_object_add(user_obj, "online_time", json_object_new_int(client->online_time));
    json_object_object_add(user_obj, "offline_time", json_object_new_int(client->offline_time));

    if (flag > 0) {
        json_object_object_add(user_obj, "ip", json_object_new_string(client->ip));
        json_object_object_add(user_obj, "ipv6", json_object_new_string(client->ipv6));
        LOG_DEBUG("all_users_callback: Added IP: %s for mac=%s\n", client->ip, client->mac);
    }

    if (flag > 1){
        json_object_object_add(user_obj, "hostname", json_object_new_string(client->hostname));
        json_object_object_add(user_obj, "nickname", json_object_new_string(client->nickname));
        LOG_DEBUG("all_users_callback: Added hostname=%s, nickname=%s for mac=%s\n", 
               client->hostname, client->nickname, client->mac);
    }

    if (flag > 2){
        struct json_object *app_array = json_object_new_array();
        app_visit_time_info_t top5_app_list[5];
        memset(top5_app_list, 0x0, sizeof(top5_app_list));
        update_top5_app(client, top5_app_list);
        int app_count = 0;
        for (i = 0; i < 5; i++)
        {
            if (top5_app_list[i].app_id == 0)
                break;

            struct json_object *app_obj = json_object_new_object();
            json_object_object_add(app_obj, "id", json_object_new_int(top5_app_list[i].app_id));
            json_object_object_add(app_obj, "name",
            json_object_new_string(jmx_safe_app_name(top5_app_list[i].app_id)));

            json_object_array_add(app_array, app_obj);
            app_count++;
        }
        json_object_object_add(user_obj, "applist", app_array);
        LOG_DEBUG("all_users_callback: Added %d apps to applist for mac=%s\n", app_count, client->mac);

        if (strlen(client->visiting_url) > 0)
            json_object_object_add(user_obj, "url", json_object_new_string(client->visiting_url));
        else
            json_object_object_add(user_obj, "url", json_object_new_string(""));
if (client->visiting_app > 0) {
    const char *visiting_app_name = jmx_safe_app_name(client->visiting_app);

    json_object_object_add(user_obj, "app",
        json_object_new_string(visiting_app_name));

    LOG_DEBUG("all_users_callback: Added visiting app=%s (id=%d), url=%s for mac=%s\n",
           visiting_app_name, client->visiting_app, client->visiting_url, client->mac);
} else {
    json_object_object_add(user_obj, "app", json_object_new_string(""));
}
        

        json_object_object_add(user_obj, "up_rate", json_object_new_int(client->up_rate));
        json_object_object_add(user_obj, "down_rate", json_object_new_int(client->down_rate));
        

        daily_hourly_stat_t *today_stat = get_today_stat(client);
        unsigned long long today_up_bytes = 0;
        unsigned long long today_down_bytes = 0;
        
        if (today_stat) {
            for (hour = 0; hour < HOURS_PER_DAY; hour++) {
                today_up_bytes += today_stat->hourly_traffic[hour].up_bytes;
                today_down_bytes += today_stat->hourly_traffic[hour].down_bytes;
            }
        }
        

        json_object_object_add(user_obj, "today_up_bytes", json_object_new_int64(today_up_bytes));
        json_object_object_add(user_obj, "today_down_bytes", json_object_new_int64(today_down_bytes));
    }
    
    json_object_array_add(users_array, user_obj);
    int new_count = json_object_array_length(users_array);
    LOG_DEBUG("all_users_callback: Successfully added user mac=%s, array length now: %d\n", 
           client->mac, new_count);
}

int compare_users(const void *a, const void *b)
{
    struct json_object *user_a = *(struct json_object **)a;
    struct json_object *user_b = *(struct json_object **)b;

    struct json_object *online_a, *online_b;
    json_object_object_get_ex(user_a, "online", &online_a);
    json_object_object_get_ex(user_b, "online", &online_b);

    int online_val_a = json_object_get_int(online_a);
    int online_val_b = json_object_get_int(online_b);

    if (online_val_a != online_val_b)
        return online_val_b - online_val_a;

    struct json_object *online_time_a, *online_time_b;
    json_object_object_get_ex(user_a, "online_time", &online_time_a);
    json_object_object_get_ex(user_b, "online_time", &online_time_b);

    int online_time_val_a = json_object_get_int(online_time_a);
    int online_time_val_b = json_object_get_int(online_time_b);

    if (online_val_a == 1 && online_val_b == 1) {

        return online_time_val_a - online_time_val_b;
    } else {

        struct json_object *offline_time_a, *offline_time_b;
        json_object_object_get_ex(user_a, "offline_time", &offline_time_a);
        json_object_object_get_ex(user_b, "offline_time", &offline_time_b);

        int offline_time_val_a = json_object_get_int(offline_time_a);
        int offline_time_val_b = json_object_get_int(offline_time_b);

        return offline_time_val_a - offline_time_val_b;
    }
}

struct json_object *jmx_api_set_nickname(struct json_object *req_obj) {
    if (!req_obj) {
        return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    struct json_object *mac_obj = json_object_object_get(req_obj, "mac");
    struct json_object *nickname_obj = json_object_object_get(req_obj, "nickname");
    
    if (!nickname_obj || !mac_obj) {
        return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    const char *mac = json_object_get_string(mac_obj);
    const char *nickname = json_object_get_string(nickname_obj);
    
    if (!mac) {
        return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    if (jmx_client_nickname_set(mac, nickname ? nickname : "") != 0) {
        LOG_ERROR("Failed to commit nickname to config.db\n");
        return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    update_client_nickname();
    reload_oaf_rule();

    return jmx_gen_api_response_data(API_CODE_SUCCESS, NULL);
}


struct json_object *jmx_api_dev_visit_list(struct json_object *req_obj) {
    if (!req_obj) {
        return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    struct json_object *mac_obj = json_object_object_get(req_obj, "mac");
    if (!mac_obj) {
        return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    const char *mac = json_object_get_string(mac_obj);
    if (!mac) {
        return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    int page = 1;
    int page_size = 15;
    struct json_object *page_obj = json_object_object_get(req_obj, "page");
    struct json_object *page_size_obj = json_object_object_get(req_obj, "page_size");
    if (page_obj) {
        page = json_object_get_int(page_obj);
        if (page < 1) page = 1;
    }
    if (page_size_obj) {
        page_size = json_object_get_int(page_size_obj);
        if (page_size < 1) page_size = 15;
    }
    
    struct json_object *root_obj = json_object_new_object();
    struct json_object *visit_array = json_object_new_array();
    
    client_node_t *node = find_client_node(mac);
    if (!node) {
        json_object_object_add(root_obj, "hostname", json_object_new_string(""));
        json_object_object_add(root_obj, "mac", json_object_new_string(mac));
        json_object_object_add(root_obj, "ip", json_object_new_string(""));
        json_object_object_add(root_obj, "ipv6", json_object_new_string(""));
        json_object_object_add(root_obj, "total_num", json_object_new_int(0));
        json_object_object_add(root_obj, "total_page", json_object_new_int(1));
        json_object_object_add(root_obj, "page", json_object_new_int(page));
        json_object_object_add(root_obj, "page_size", json_object_new_int(page_size));
        json_object_object_add(root_obj, "list", visit_array);
        return jmx_gen_api_response_data(API_CODE_SUCCESS, root_obj);
    }
    
    json_object_object_add(root_obj, "hostname", json_object_new_string(node->hostname));
    json_object_object_add(root_obj, "mac", json_object_new_string(node->mac));
    json_object_object_add(root_obj, "ip", json_object_new_string(node->ip));
    

    struct json_object *online_array = json_object_new_array();
    struct json_object *offline_array = json_object_new_array();
    visit_info_t *p_info = NULL;

    int online_num = 0;
    int offline_num = 0;

    list_for_each_entry(p_info, &node->online_visit, visit) {
        int total_time = p_info->latest_time - p_info->first_time;
        struct json_object *visit_obj = json_object_new_object();
        json_object_object_add(visit_obj, "name", json_object_new_string(jmx_safe_app_name(p_info->appid)));
        json_object_object_add(visit_obj, "id", json_object_new_int(p_info->appid));
        json_object_object_add(visit_obj, "act", json_object_new_int(p_info->action));
        json_object_object_add(visit_obj, "online", json_object_new_int(1));
        json_object_object_add(visit_obj, "ft", json_object_new_int(p_info->first_time));
        json_object_object_add(visit_obj, "lt", json_object_new_int(p_info->latest_time));
        json_object_object_add(visit_obj, "tt", json_object_new_int(total_time));
        json_object_array_add(online_array, visit_obj);
        online_num++;
    }

    list_for_each_entry(p_info, &node->visit, visit) {
        int total_time = p_info->latest_time - p_info->first_time;
        struct json_object *visit_obj = json_object_new_object();
        json_object_object_add(visit_obj, "name", json_object_new_string(jmx_safe_app_name(p_info->appid)));
        json_object_object_add(visit_obj, "id", json_object_new_int(p_info->appid));
        json_object_object_add(visit_obj, "act", json_object_new_int(p_info->action));
        json_object_object_add(visit_obj, "online", json_object_new_int(0));
        json_object_object_add(visit_obj, "ft", json_object_new_int(p_info->first_time));
        json_object_object_add(visit_obj, "lt", json_object_new_int(p_info->latest_time));
        json_object_object_add(visit_obj, "tt", json_object_new_int(total_time));
        json_object_array_add(offline_array, visit_obj);
        offline_num++;
    }

    json_object_array_sort(online_array, compare_lt);
    json_object_array_sort(offline_array, compare_lt);

    int total_num = online_num + offline_num;
    int total_page = (total_num + page_size - 1) / page_size;
    if (total_page < 1) total_page = 1;
    if (page > total_page) page = total_page;
    

    struct json_object *paged_array = json_object_new_array();
    int start_idx = (page - 1) * page_size;
    int end_idx = start_idx + page_size;
    if (end_idx > total_num) end_idx = total_num;
    
    int i;
    for (i = start_idx; i < end_idx; i++) {
        struct json_object *item = NULL;
        if (i < online_num) {
            item = json_object_array_get_idx(online_array, i);
        } else {
            item = json_object_array_get_idx(offline_array, i - online_num);
        }
        if (item) {
            json_object_get(item);
            json_object_array_add(paged_array, item);
        }
    }
    
    json_object_put(online_array);
    json_object_put(offline_array);
    
    json_object_object_add(root_obj, "total_num", json_object_new_int(total_num));
    json_object_object_add(root_obj, "total_page", json_object_new_int(total_page));
    json_object_object_add(root_obj, "page", json_object_new_int(page));
    json_object_object_add(root_obj, "page_size", json_object_new_int(page_size));
    json_object_object_add(root_obj, "list", paged_array);
    
    return jmx_gen_api_response_data(API_CODE_SUCCESS, root_obj);
}


struct json_object *jmx_api_dev_visit_time(struct json_object *req_obj) {
    if (!req_obj) {
        return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    struct json_object *mac_obj = json_object_object_get(req_obj, "mac");
    if (!mac_obj) {
        return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    const char *mac = json_object_get_string(mac_obj);
    if (!mac) {
        return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    struct app_visit_stat_info info;
    memset((char *)&info, 0x0, sizeof(info));
    update_app_visit_time_list(mac, &info);
    
    struct json_object *resp_obj = json_object_new_object();
    struct json_object *app_info_array = json_object_new_array();
    json_object_object_add(resp_obj, "list", app_info_array);
    json_object_object_add(resp_obj, "total_num", json_object_new_int(info.num));
    
    int i;
    for (i = 0; i < info.num; i++) {
        struct json_object *app_info_obj = json_object_new_object();
        json_object_object_add(app_info_obj, "id", json_object_new_int(info.visit_list[i].app_id));
        json_object_object_add(app_info_obj, "name", json_object_new_string(jmx_safe_app_name(info.visit_list[i].app_id)));
        json_object_object_add(app_info_obj, "t", json_object_new_int(info.visit_list[i].total_time));
        json_object_array_add(app_info_array, app_info_obj);
    }
    
    return jmx_gen_api_response_data(API_CODE_SUCCESS, resp_obj);
}


struct json_object *jmx_api_app_class_visit_time(struct json_object *req_obj) {
    if (!req_obj) {
        return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    struct json_object *mac_obj = json_object_object_get(req_obj, "mac");
    if (!mac_obj) {
        return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    const char *mac = json_object_get_string(mac_obj);
    if (!mac) {
        return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    int app_class_visit_time[MAX_APP_TYPE];
    memset(app_class_visit_time, 0x0, sizeof(app_class_visit_time));
    update_app_class_visit_time_list(mac, app_class_visit_time);
    
    struct json_object *resp_obj = json_object_new_object();
    struct json_object *app_class_array = json_object_new_array();
    json_object_object_add(resp_obj, "class_list", app_class_array);
    
    extern int g_cur_class_num;
    int i;
    for (i = 0; i < MAX_APP_TYPE; i++) {
        if (i >= g_cur_class_num)
            break;
        struct json_object *app_class_obj = json_object_new_object();
        json_object_object_add(app_class_obj, "type", json_object_new_int(i));
        json_object_object_add(app_class_obj, "name", json_object_new_string(CLASS_NAME_TABLE ? CLASS_NAME_TABLE[i] : "unknown"));
        json_object_object_add(app_class_obj, "visit_time", json_object_new_int(app_class_visit_time[i]));
        json_object_array_add(app_class_array, app_class_obj);
    }
    
    return jmx_gen_api_response_data(API_CODE_SUCCESS, resp_obj);
}


struct json_object *jmx_api_dev_list(struct json_object *req_obj) {
    int i;
    struct json_object *root_obj = json_object_new_object();
    struct json_object *dev_array = json_object_new_array();
    
    extern struct list_head client_list;
    
    client_node_t *node = NULL;
    list_for_each_entry(node, &client_list, client) {
        struct json_object *dev_obj = json_object_new_object();
        json_object_object_add(dev_obj, "mac", json_object_new_string(node->mac));
        json_object_object_add(dev_obj, "ip", json_object_new_string(node->ip));
        json_object_object_add(dev_obj, "ipv6", json_object_new_string(node->ipv6));
        json_object_object_add(dev_obj, "hostname", json_object_new_string(node->hostname));
        json_object_object_add(dev_obj, "nickname", json_object_new_string(node->nickname));
        json_object_object_add(dev_obj, "online", json_object_new_int(node->online));
        
        app_visit_time_info_t top5_app_list[5] = {0};
        update_top5_app(node, top5_app_list);
        
        struct json_object *visit_info_array = json_object_new_array();
        for (i = 0; i < 5; i++) {
            if (top5_app_list[i].app_id == 0)
                break;
            struct json_object *visit_info_obj = json_object_new_object();
            json_object_object_add(visit_info_obj, "appid", json_object_new_int(top5_app_list[i].app_id));
            json_object_object_add(visit_info_obj, "appname", json_object_new_string(jmx_safe_app_name(top5_app_list[i].app_id)));
            json_object_object_add(visit_info_obj, "latest_time", json_object_new_int64(top5_app_list[i].total_time));
            json_object_array_add(visit_info_array, visit_info_obj);
        }
        json_object_object_add(dev_obj, "visit_info", visit_info_array);
        json_object_array_add(dev_array, dev_obj);
    }
    
    json_object_object_add(root_obj, "dev_list", dev_array);
    
    return jmx_gen_api_response_data(API_CODE_SUCCESS, root_obj);
}


struct json_object *jmx_api_class_list(struct json_object *req_obj) {
    struct json_object *class_list = json_object_new_array();
    
    if (parse_signature_classes(class_list) != 0) {
        json_object_put(class_list);
        return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    struct json_object *response = json_object_new_object();
    json_object_object_add(response, "class_list", class_list);
    
    return jmx_gen_api_response_data(API_CODE_SUCCESS, response);
}


struct json_object *jmx_api_get_all_users(struct json_object *req_obj) {
    if (!req_obj) {
        return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    int flag = 0;
    int page = 1;
    int page_size = 15;
    
    struct json_object *flag_obj = json_object_object_get(req_obj, "flag");
    struct json_object *page_obj = json_object_object_get(req_obj, "page");
    struct json_object *page_size_obj = json_object_object_get(req_obj, "page_size");
    
    if (flag_obj) {
        flag = json_object_get_int(flag_obj);
    }
    if (page_obj) {
        page = json_object_get_int(page_obj);
        if (page < 1) page = 1;
    }
    if (page_size_obj) {
        page_size = json_object_get_int(page_size_obj);
        if (page_size < 1) page_size = 15;
    }
    
    struct uci_context *uci_ctx = uci_alloc_context();
    if (!uci_ctx) {
        LOG_ERROR("Failed to allocate UCI context\n");
        return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    all_users_info_t au_info;
    au_info.flag = flag;
    au_info.users_array = json_object_new_array();
    if (!au_info.users_array) {
        LOG_ERROR("Failed to create users_array\n");
        uci_free_context(uci_ctx);
        return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    update_client_nickname();
    update_client_visiting_info();
    client_foreach(&au_info, all_users_callback);
    
    json_object_array_sort(au_info.users_array, compare_users);
    

    int total_num = json_object_array_length(au_info.users_array);
    int total_page = (total_num + page_size - 1) / page_size;
    if (total_page < 1) total_page = 1;
    if (page > total_page) page = total_page;
    

    struct json_object *paged_array = json_object_new_array();
    int start_idx = (page - 1) * page_size;
    int end_idx = start_idx + page_size;
    if (end_idx > total_num) end_idx = total_num;
    
    int i;
    for (i = start_idx; i < end_idx; i++) {
        struct json_object *item = json_object_array_get_idx(au_info.users_array, i);
        if (item) {
            json_object_get(item);
            json_object_array_add(paged_array, item);
        }
    }
    
    json_object_put(au_info.users_array);
    
    struct json_object *data_obj = json_object_new_object();
    json_object_object_add(data_obj, "list", paged_array);
    json_object_object_add(data_obj, "total_num", json_object_new_int(total_num));
    json_object_object_add(data_obj, "total_page", json_object_new_int(total_page));
    json_object_object_add(data_obj, "page", json_object_new_int(page));
    json_object_object_add(data_obj, "page_size", json_object_new_int(page_size));
    
    uci_free_context(uci_ctx);
    
    return jmx_gen_api_response_data(API_CODE_SUCCESS, data_obj);
}


struct json_object *jmx_api_get_oaf_status(struct json_object *req_obj) {
    struct json_object *data_obj = json_object_new_object();
    char result[128] = {0};
    char kernel_version[128] = {0};
    int enable = 0;
    int ret = 0;
    int engine_status = 0;
    
    ret = exec_with_result_line("cat /proc/sys/oaf/enable", result, sizeof(result));
    if (strlen(result) == 0) {
        engine_status = 0;
        enable = 0;
    } else {
        enable = atoi(result);
        engine_status = 1;
    }
    
    json_object_object_add(data_obj, "enable", json_object_new_int(enable));
    json_object_object_add(data_obj, "version", json_object_new_string(OAF_VERSION));
    json_object_object_add(data_obj, "engine_status", json_object_new_int(engine_status));
    
    ret = exec_with_result_line("cat /proc/sys/oaf/version", kernel_version, sizeof(kernel_version));
    if (ret >= 0) {
        json_object_object_add(data_obj, "engine_version", json_object_new_string(kernel_version));
    } else {
        json_object_object_add(data_obj, "engine_version", json_object_new_string(""));
    }
    
    ret = exec_with_result_line("uname -r", kernel_version, sizeof(kernel_version));
    if (ret >= 0) {
        json_object_object_add(data_obj, "kernel_version", json_object_new_string(kernel_version));
    } else {
        json_object_object_add(data_obj, "kernel_version", json_object_new_string(""));
    }
    
    return jmx_gen_api_response_data(API_CODE_SUCCESS, data_obj);
}


struct json_object *jmx_api_visit_list(struct json_object *req_obj) {
    const char *mac = NULL;
    
    if (req_obj) {
        struct json_object *mac_obj = json_object_object_get(req_obj, "mac");
        if (mac_obj) {
            mac = json_object_get_string(mac_obj);
        }
    }
    
    struct json_object *root_obj = json_object_new_object();
    struct json_object *dev_array = json_object_new_array();
    
    extern struct list_head client_list;
    client_node_t *node = NULL;
    visit_info_t *p_info = NULL;
    
    list_for_each_entry(node, &client_list, client) {
        if (mac && strcmp(mac, node->mac)) {
            continue;
        }
        
        struct json_object *dev_obj = json_object_new_object();
        json_object_object_add(dev_obj, "hostname", json_object_new_string(node->hostname));
        json_object_object_add(dev_obj, "mac", json_object_new_string(node->mac));
        json_object_object_add(dev_obj, "ip", json_object_new_string(node->ip));
        json_object_object_add(dev_obj, "ipv6", json_object_new_string(node->ipv6));
        
        struct json_object *online_array = json_object_new_array();
        struct json_object *offline_array = json_object_new_array();

        list_for_each_entry(p_info, &node->online_visit, visit) {
            int total_time = p_info->latest_time - p_info->first_time;
            
            struct json_object *visit_obj = json_object_new_object();
            json_object_object_add(visit_obj, "appname", json_object_new_string(jmx_safe_app_name(p_info->appid)));
            json_object_object_add(visit_obj, "appid", json_object_new_int(p_info->appid));
            json_object_object_add(visit_obj, "latest_action", json_object_new_int(p_info->action));
            json_object_object_add(visit_obj, "online", json_object_new_int(1));
            json_object_object_add(visit_obj, "first_time", json_object_new_int(p_info->first_time));
            json_object_object_add(visit_obj, "latest_time", json_object_new_int(p_info->latest_time));
            json_object_object_add(visit_obj, "total_time", json_object_new_int(total_time));
            json_object_array_add(online_array, visit_obj);
        }

        list_for_each_entry(p_info, &node->visit, visit) {
            char *first_time_str = format_time(p_info->first_time);
            char *latest_time_str = format_time(p_info->latest_time);
            int total_time = p_info->latest_time - p_info->first_time;
            
            struct json_object *visit_obj = json_object_new_object();
            json_object_object_add(visit_obj, "appname", json_object_new_string(jmx_safe_app_name(p_info->appid)));
            json_object_object_add(visit_obj, "appid", json_object_new_int(p_info->appid));
            json_object_object_add(visit_obj, "latest_action", json_object_new_int(p_info->action));
            json_object_object_add(visit_obj, "online", json_object_new_int(0));
            json_object_object_add(visit_obj, "first_time", json_object_new_int(p_info->first_time));
            json_object_object_add(visit_obj, "latest_time", json_object_new_int(p_info->latest_time));
            json_object_object_add(visit_obj, "total_time", json_object_new_int(total_time));
            json_object_array_add(offline_array, visit_obj);
            
            if (first_time_str)
                free(first_time_str);
            if (latest_time_str)
                free(latest_time_str);
        }

        json_object_array_sort(online_array, compare_lt);
        json_object_array_sort(offline_array, compare_lt);

        struct json_object *visit_array = json_object_new_array();
        int online_num = json_object_array_length(online_array);
        int offline_num = json_object_array_length(offline_array);
        int idx;
        for (idx = 0; idx < online_num; idx++) {
            struct json_object *item = json_object_array_get_idx(online_array, idx);
            if (item) {
                json_object_get(item);
                json_object_array_add(visit_array, item);
            }
        }
        for (idx = 0; idx < offline_num; idx++) {
            struct json_object *item = json_object_array_get_idx(offline_array, idx);
            if (item) {
                json_object_get(item);
                json_object_array_add(visit_array, item);
            }
        }

        json_object_put(online_array);
        json_object_put(offline_array);

        json_object_object_add(dev_obj, "visit_info", visit_array);
        json_object_array_add(dev_array, dev_obj);
    }
    
    json_object_object_add(root_obj, "dev_list", dev_array);
    
    return jmx_gen_api_response_data(API_CODE_SUCCESS, root_obj);
}


static char *get_model(void) {
    char model[32] = {0};
    struct json_object *board_json = json_object_from_file("/etc/board.json");
    if (!board_json) {
        strcpy(model, "Unknown");
    } else {
        struct json_object *model_obj = json_object_object_get(board_json, "model");
        if (model_obj) {
            struct json_object *name_obj = json_object_object_get(model_obj, "name");
            if (name_obj)
                strncpy(model, json_object_get_string(name_obj), sizeof(model) - 1);
            else
                strcpy(model, "Unknown");
        } else {
            strcpy(model, "Unknown");
        }
    }
    if (board_json)
        json_object_put(board_json);
    

    if (strcmp(model, "Unknown") == 0) {
        char buf[256] = {0};
        if (exec_with_result_line("cat /proc/device-tree/model 2>/dev/null || cat /tmp/sysinfo/board_name 2>/dev/null || echo Unknown", buf, sizeof(buf)) == 0 && strlen(buf) > 0) {
            strncpy(model, buf, sizeof(model) - 1);
        }
    }
    
    return strdup(model);
}


static int get_uptime(void) {
    FILE *uptime_fp = fopen("/proc/uptime", "r");
    if (uptime_fp) {
        double uptime_sec = 0;
        if (fscanf(uptime_fp, "%lf", &uptime_sec) == 1) {
            fclose(uptime_fp);
            return (int)uptime_sec;
        }
        fclose(uptime_fp);
    }
    return 0;
}


static int read_file_buf(const char *file, char *buf, int len) {
    if (!file || !buf || len <= 0)
        return -1;
    
    int fd = open(file, O_RDONLY | O_NONBLOCK, 0644);
    if (fd < 0) {
        return -1;
    }
    
    int size = read(fd, buf, len - 1);
    close(fd);
    
    if (size > 0) {
        buf[size] = '\0';
        str_trim(buf);
        return size;
    }
    
    return -1;
}








static int parse_tempinfo_output(char *output, int *cpu_temp, int *wifi_temp) {
    if (!output || !cpu_temp || !wifi_temp) {
        return -1;
    }
    

    *cpu_temp = -1;
    *wifi_temp = -1;
    

    char *cpu_label = strstr(output, "CPU:");
    if (cpu_label) {
        cpu_label += 4; // 跳过 "CPU:"

        while (*cpu_label == ' ' || *cpu_label == '\t') {
            cpu_label++;
        }

        char *celsius_pos = strstr(cpu_label, "°C");
        if (celsius_pos && celsius_pos > cpu_label) {

            char temp_str[64] = {0};
            size_t len = celsius_pos - cpu_label;
            if (len < sizeof(temp_str)) {
                strncpy(temp_str, cpu_label, len);
                temp_str[len] = '\0';

                float cpu_temp_float = 0.0;
                if (sscanf(temp_str, "%f", &cpu_temp_float) == 1) {
                    *cpu_temp = (int)(cpu_temp_float + 0.5); // 四舍五入

                    if (*cpu_temp < -50 || *cpu_temp > 150) {
                        *cpu_temp = -1;
                    }
                }
            }
        }
    }
    

    char *wifi_label = strstr(output, "WiFi:");
    if (wifi_label) {
        wifi_label += 5; // 跳过 "WiFi:"

        while (*wifi_label == ' ' || *wifi_label == '\t') {
            wifi_label++;
        }

        char *celsius_pos = strstr(wifi_label, "°C");
        if (celsius_pos && celsius_pos > wifi_label) {

            char temp_str[64] = {0};
            size_t len = celsius_pos - wifi_label;
            if (len < sizeof(temp_str)) {
                strncpy(temp_str, wifi_label, len);
                temp_str[len] = '\0';

                float wifi_temp_float = 0.0;
                if (sscanf(temp_str, "%f", &wifi_temp_float) == 1) {
                    *wifi_temp = (int)(wifi_temp_float + 0.5); // 四舍五入

                    if (*wifi_temp < -50 || *wifi_temp > 150) {
                        *wifi_temp = -1;
                    }
                }
            }
        }
    }
    

    if (*cpu_temp > 0 || *wifi_temp > 0) {
        return 0;
    }
    
    return -1;
}


static int get_cpu_temperature(void) {
    int cpu_temp = -1;
    int wifi_temp = -1; 
    int i;

    if (access("/sbin/tempinfo", F_OK) == 0) {
        FILE *fp = popen("/sbin/tempinfo", "r");
        if (fp) {
            char output[256] = {0};
            char line[256] = {0};
            size_t total_read = 0;
            

            while (fgets(line, sizeof(line), fp) != NULL && total_read < sizeof(output) - 1) {
                size_t line_len = strlen(line);
                if (total_read + line_len < sizeof(output) - 1) {
                    strncpy(output + total_read, line, line_len);
                    total_read += line_len;
                    output[total_read] = '\0';
                } else {
                    break;
                }
            }
            pclose(fp);
            

            if (parse_tempinfo_output(output, &cpu_temp, &wifi_temp) == 0 && cpu_temp > 0) {
                return cpu_temp;
            }
        }
    }
    

    char temp_buf[64] = {0};
    int temp_millidegrees = 0;
    int temp_degrees = 0;
    


    if (read_file_buf("/sys/class/thermal/thermal_zone0/temp", temp_buf, sizeof(temp_buf)) > 0) {
        temp_millidegrees = atoi(temp_buf);
        if (temp_millidegrees > 0) {

            temp_degrees = temp_millidegrees / 1000;

            if (temp_degrees >= -50 && temp_degrees <= 150) {
                return temp_degrees;
            }
        }
    }
    


    for (i = 0; i < 10; i++) {
        char path[256] = {0};
        snprintf(path, sizeof(path), "/sys/class/thermal/thermal_zone%d/temp", i);
        if (read_file_buf(path, temp_buf, sizeof(temp_buf)) > 0) {
            temp_millidegrees = atoi(temp_buf);
            if (temp_millidegrees > 0) {
                temp_degrees = temp_millidegrees / 1000;
                if (temp_degrees >= -50 && temp_degrees <= 150) {
                    return temp_degrees;
                }
            }
        }
    }
    

    return -1;
}



static int read_proc_stat_cpu(unsigned long long *idle, unsigned long long *total) {
    FILE *fp;
    char cpu[16];
    unsigned long long user = 0, nice = 0, system = 0, idle_v = 0;
    unsigned long long iowait = 0, irq = 0, softirq = 0, steal = 0;

    if (!idle || !total)
        return -1;

    fp = fopen("/proc/stat", "r");
    if (!fp)
        return -1;

    if (fscanf(fp, "%15s %llu %llu %llu %llu %llu %llu %llu %llu",
               cpu, &user, &nice, &system, &idle_v, &iowait,
               &irq, &softirq, &steal) < 5) {
        fclose(fp);
        return -1;
    }
    fclose(fp);

    if (strcmp(cpu, "cpu") != 0)
        return -1;

    *idle = idle_v + iowait;
    *total = user + nice + system + idle_v + iowait + irq + softirq + steal;
    return 0;
}

static int get_cpu_usage_percent(void) {
    unsigned long long idle1 = 0, total1 = 0, idle2 = 0, total2 = 0;
    unsigned long long idle_diff, total_diff;
    int usage;

    if (read_proc_stat_cpu(&idle1, &total1) < 0)
        return 0;
    usleep(100000);
    if (read_proc_stat_cpu(&idle2, &total2) < 0)
        return 0;

    if (total2 <= total1)
        return 0;
    total_diff = total2 - total1;
    idle_diff = (idle2 >= idle1) ? (idle2 - idle1) : 0;
    if (idle_diff > total_diff)
        idle_diff = total_diff;

    usage = (int)((100ULL * (total_diff - idle_diff) + total_diff / 2) / total_diff);
    if (usage < 0) usage = 0;
    if (usage > 100) usage = 100;
    return usage;
}

static int get_wifi_temperature(void) {
    int cpu_temp = -1; // 这里不需要，但函数需要这个参数
    int wifi_temp = -1;
    int i;

    if (access("/sbin/tempinfo", F_OK) == 0) {
        FILE *fp = popen("/sbin/tempinfo", "r");
        if (fp) {
            char output[256] = {0};
            char line[256] = {0};
            size_t total_read = 0;
            

            while (fgets(line, sizeof(line), fp) != NULL && total_read < sizeof(output) - 1) {
                size_t line_len = strlen(line);
                if (total_read + line_len < sizeof(output) - 1) {
                    strncpy(output + total_read, line, line_len);
                    total_read += line_len;
                    output[total_read] = '\0';
                } else {
                    break;
                }
            }
            pclose(fp);
            

            if (parse_tempinfo_output(output, &cpu_temp, &wifi_temp) == 0 && wifi_temp > 0) {
                return wifi_temp;
            }
        }
    }
    

    char temp_buf[64] = {0};
    int temp_degrees = 0;
    


    if (read_file_buf("/sys/class/ieee80211/phy0/temperature", temp_buf, sizeof(temp_buf)) > 0) {
        temp_degrees = atoi(temp_buf);

        if (temp_degrees >= -50 && temp_degrees <= 150) {
            return temp_degrees;
        }
    }
    

    for (i = 0; i < 10; i++) {
        char path[256] = {0};
        snprintf(path, sizeof(path), "/sys/class/ieee80211/phy%d/temperature", i);
        if (read_file_buf(path, temp_buf, sizeof(temp_buf)) > 0) {
            temp_degrees = atoi(temp_buf);
            if (temp_degrees >= -50 && temp_degrees <= 150) {
                return temp_degrees;
            }
        }
    }
    

    return -1;
}


static int get_cpu_model_name_from_proc(char *model_name, size_t len);
static int get_cpu_model_name_from_ubus(char *model_name, size_t len);


static int get_cpu_model_name_from_proc(char *model_name, size_t len) {
    FILE *fp = fopen("/proc/cpuinfo", "r");
    if (!fp) {
        return -1;
    }
    
    char line[256] = {0};
    int found = 0;
    
    while (fgets(line, sizeof(line), fp)) {

        if (strncmp(line, "model name", 10) == 0) {
            char *colon = strchr(line, ':');
            if (colon) {

                char *name_start = colon + 1;

                while (*name_start == ' ' || *name_start == '\t') {
                    name_start++;
                }

                char *newline = strchr(name_start, '\n');
                if (newline) {
                    *newline = '\0';
                }

                char *carriage = strchr(name_start, '\r');
                if (carriage) {
                    *carriage = '\0';
                }

                strncpy(model_name, name_start, len - 1);
                model_name[len - 1] = '\0';
                str_trim(model_name);
                found = 1;
                break;
            }
        }

        else if (strncmp(line, "cpu model", 9) == 0 || strncmp(line, "Processor", 9) == 0) {
            char *colon = strchr(line, ':');
            if (colon) {
                char *name_start = colon + 1;
                while (*name_start == ' ' || *name_start == '\t') {
                    name_start++;
                }
                char *newline = strchr(name_start, '\n');
                if (newline) {
                    *newline = '\0';
                }
                char *carriage = strchr(name_start, '\r');
                if (carriage) {
                    *carriage = '\0';
                }
                strncpy(model_name, name_start, len - 1);
                model_name[len - 1] = '\0';
                str_trim(model_name);
                found = 1;
                break;
            }
        }
    }
    
    fclose(fp);
    
    if (!found) {
        return -1;
    }
    
    LOG_DEBUG("get_cpu_model_name_from_proc: found CPU model: %s\n", model_name);
    return 0;
}


static int get_cpu_model_name(char *model_name, size_t len) {

    if (get_cpu_model_name_from_proc(model_name, len) == 0) {
        return 0;
    }
    

    LOG_DEBUG("get_cpu_model_name: CPU model name not found in /proc/cpuinfo, trying ubus call system board\n");
    if (get_cpu_model_name_from_ubus(model_name, len) == 0) {
        return 0;
    }
    
    return -1;
}


static int get_cpu_model_name_from_ubus(char *model_name, size_t len) {

    FILE *ubus_fp = popen("ubus call system board 2>/dev/null", "r");
    if (!ubus_fp) {
        LOG_ERROR("get_cpu_model_name_from_ubus: failed to call ubus system board\n");
        return -1;
    }
    

    char ubus_output[2048] = {0};
    size_t total_read = 0;
    char line_buf[256] = {0};
    
    while (fgets(line_buf, sizeof(line_buf), ubus_fp) && total_read < sizeof(ubus_output) - 1) {
        size_t line_len = strlen(line_buf);
        if (total_read + line_len < sizeof(ubus_output) - 1) {
            memcpy(ubus_output + total_read, line_buf, line_len);
            total_read += line_len;
            ubus_output[total_read] = '\0';
        } else {
            break;
        }
    }
    pclose(ubus_fp);
    
    if (strlen(ubus_output) == 0) {
        LOG_ERROR("get_cpu_model_name_from_ubus: ubus output is empty\n");
        return -1;
    }
    

    struct json_object *board_obj = json_tokener_parse(ubus_output);
    if (!board_obj) {
        LOG_ERROR("get_cpu_model_name_from_ubus: failed to parse ubus JSON output\n");
        return -1;
    }
    
    int found = 0;
    

    struct json_object *release_obj = json_object_object_get(board_obj, "release");
    if (release_obj) {
        struct json_object *target_obj = json_object_object_get(release_obj, "target");
        if (target_obj) {
            const char *target_str = json_object_get_string(target_obj);
            if (target_str && strlen(target_str) > 0) {
                strncpy(model_name, target_str, len - 1);
                model_name[len - 1] = '\0';
                str_trim(model_name);
                found = 1;
            }
        }
    }
    

    if (!found) {
        struct json_object *system_obj = json_object_object_get(board_obj, "system");
        if (system_obj) {
            const char *system_str = json_object_get_string(system_obj);
            if (system_str && strlen(system_str) > 0) {
                strncpy(model_name, system_str, len - 1);
                model_name[len - 1] = '\0';
                str_trim(model_name);
                found = 1;
            }
        }
    }
    
    json_object_put(board_obj);
    
    if (!found) {
        LOG_ERROR("get_cpu_model_name_from_ubus: CPU model name not found in ubus system board\n");
        return -1;
    }
    
    LOG_DEBUG("get_cpu_model_name_from_ubus: found CPU model: %s\n", model_name);
    return 0;
}


static int get_os_release_field(const char *field_name, char *value, size_t len) {
    FILE *fp = fopen("/etc/os-release", "r");
    if (!fp) {
        LOG_ERROR("get_os_release_field: failed to open /etc/os-release\n");
        return -1;
    }
    
    char line[256] = {0};
    size_t field_len = strlen(field_name);
    int found = 0;
    
    while (fgets(line, sizeof(line), fp)) {

        if (strncmp(line, field_name, field_len) == 0 && line[field_len] == '=') {
            char *value_start = line + field_len + 1;

            if (*value_start == '"' || *value_start == '\'') {
                value_start++;
            }
            

            char *value_end = value_start;
            while (*value_end != '\0' && *value_end != '\n' && *value_end != '\r') {
                if ((*value_end == '"' || *value_end == '\'') && value_end > value_start) {
                    break;
                }
                value_end++;
            }
            

            size_t value_size = value_end - value_start;
            if (value_size > 0 && value_size < len) {
                strncpy(value, value_start, value_size);
                value[value_size] = '\0';
                str_trim(value);
                found = 1;
                break;
            }
        }
    }
    
    fclose(fp);
    
    if (!found) {
        LOG_ERROR("get_os_release_field: field %s not found in /etc/os-release\n", field_name);
        return -1;
    }
    
    LOG_DEBUG("get_os_release_field: found %s = %s\n", field_name, value);
    return 0;
}


static struct json_object *get_dashboard_system_status(void) {
    struct json_object *system_status = json_object_new_object();
    char buf[256] = {0};
    char result[128] = {0};
	int hour;
    

    char *model = get_model();
    json_object_object_add(system_status, "model", json_object_new_string(model));
    free(model);
    

    char cpu_model_name[256] = {0};
    if (get_cpu_model_name(cpu_model_name, sizeof(cpu_model_name)) == 0) {
        json_object_object_add(system_status, "cpu_model_name", json_object_new_string(cpu_model_name));
    } else {
        json_object_object_add(system_status, "cpu_model_name", json_object_new_string("Unknown"));
    }
    

    char hostname[128] = {0};
    if (read_file_buf("/proc/sys/kernel/hostname", hostname, sizeof(hostname)) > 0) {
        json_object_object_add(system_status, "hostname", json_object_new_string(hostname));
    } else {
        json_object_object_add(system_status, "hostname", json_object_new_string("Unknown"));
    }
    

    char openwrt_version[64] = {0};
    if (get_os_release_field("VERSION", openwrt_version, sizeof(openwrt_version)) == 0) {
        json_object_object_add(system_status, "openwrt_version", json_object_new_string(openwrt_version));
    } else {
        json_object_object_add(system_status, "openwrt_version", json_object_new_string("Unknown"));
    }
    

    char arch[64] = {0};
    if (get_os_release_field("OPENWRT_ARCH", arch, sizeof(arch)) == 0) {
        json_object_object_add(system_status, "arch", json_object_new_string(arch));
    } else {
        json_object_object_add(system_status, "arch", json_object_new_string("Unknown"));
    }
    

    char jmx_version_buf[32] = {0};
    if (read_file_buf("/etc/jmx_version", jmx_version_buf, sizeof(jmx_version_buf)) > 0) {
        str_trim(jmx_version_buf);
        json_object_object_add(system_status, "jmx_version", json_object_new_string(jmx_version_buf));
    } else {

        if (read_file_buf("/etc/version", jmx_version_buf, sizeof(jmx_version_buf)) > 0) {
            str_trim(jmx_version_buf);
            json_object_object_add(system_status, "jmx_version", json_object_new_string(jmx_version_buf));
        } else {
            json_object_object_add(system_status, "jmx_version", json_object_new_string("Unknown"));
        }
    }
    

    memset(buf, 0, sizeof(buf));
    if (exec_with_result_line("uname -r", buf, sizeof(buf)) == 0 && strlen(buf) > 0) {
        str_trim(buf);
        json_object_object_add(system_status, "kernel_version", json_object_new_string(buf));
    } else {
        json_object_object_add(system_status, "kernel_version", json_object_new_string("Unknown"));
    }
    

    int uptime = get_uptime();
    json_object_object_add(system_status, "uptime", json_object_new_int(uptime));
    

    memset(result, 0, sizeof(result));
    int total_mem_kb = 0;
    int used_mem_kb = 0;
    if (exec_with_result_line("free | grep Mem | awk '{print $2}'", result, sizeof(result)) == 0) {
        total_mem_kb = atoi(result);
    }
    memset(result, 0, sizeof(result));
    if (exec_with_result_line("free | grep Mem | awk '{print $3}'", result, sizeof(result)) == 0) {
        used_mem_kb = atoi(result);
    }
    

    json_object_object_add(system_status, "total_mem", json_object_new_int(total_mem_kb));
    json_object_object_add(system_status, "used_mem", json_object_new_int(used_mem_kb));
    

    memset(result, 0, sizeof(result));
    int cpu_usage = get_cpu_usage_percent();

    snprintf(buf, sizeof(buf), "%d", cpu_usage);
    json_object_object_add(system_status, "cpu", json_object_new_string(buf));
    json_object_object_add(system_status, "cpu_percent", json_object_new_int(cpu_usage));

    int connections = 0;
    memset(result, 0, sizeof(result));

    if (exec_with_result_line("cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null", result, sizeof(result)) == 0) {
        connections = atoi(result);
    }
    json_object_object_add(system_status, "connections", json_object_new_int(connections));
    
    

    extern struct list_head client_list;
    int online_client_num = 0;
    client_node_t *client = NULL;
    list_for_each_entry(client, &client_list, client) {
        if (client->online == 1) {
            online_client_num++;
        }
    }
    json_object_object_add(system_status, "client_num", json_object_new_int(online_client_num));
    

    struct json_object *storage_obj = json_object_new_object();
    FILE *df_fp = popen("df -k", "r");
    if (df_fp) {
        char line[512];
        int found_tmp = 0, found_root = 0, found_boot = 0;
        

        if (fgets(line, sizeof(line), df_fp)) {

            while (fgets(line, sizeof(line), df_fp)) {
                char filesystem[256] = {0};
                unsigned long long total_kb = 0, used_kb = 0;
                unsigned long long available_kb = 0;  // 仅用于解析，不返回
                int use_percent = 0;  // 仅用于解析，不返回
                char mount_point[256] = {0};
                


                if (sscanf(line, "%255s %llu %llu %llu %d%% %255s", 
                          filesystem, &total_kb, &used_kb, &available_kb, &use_percent, mount_point) >= 6) {

                    if (strcmp(mount_point, "/tmp") == 0 && !found_tmp) {
                        struct json_object *tmp_obj = json_object_new_object();
                        json_object_object_add(tmp_obj, "total_kb", json_object_new_int64(total_kb));
                        json_object_object_add(tmp_obj, "used_kb", json_object_new_int64(used_kb));
                        json_object_object_add(storage_obj, "tmp", tmp_obj);
                        found_tmp = 1;
                    } else if (strcmp(mount_point, "/") == 0 && !found_root) {
                        struct json_object *root_obj = json_object_new_object();
                        json_object_object_add(root_obj, "total_kb", json_object_new_int64(total_kb));
                        json_object_object_add(root_obj, "used_kb", json_object_new_int64(used_kb));
                        json_object_object_add(storage_obj, "root", root_obj);
                        found_root = 1;
                    } else if (strcmp(mount_point, "/boot") == 0 && !found_boot) {
                        struct json_object *boot_obj = json_object_new_object();
                        json_object_object_add(boot_obj, "total_kb", json_object_new_int64(total_kb));
                        json_object_object_add(boot_obj, "used_kb", json_object_new_int64(used_kb));
                        json_object_object_add(storage_obj, "boot", boot_obj);
                        found_boot = 1;
                    }
                }
                

                if (found_tmp && found_root && found_boot) {
                    break;
                }
            }
        }
        pclose(df_fp);
    }
    

    if (!json_object_object_get(storage_obj, "tmp")) {
        struct json_object *tmp_obj = json_object_new_object();
        json_object_object_add(tmp_obj, "total_kb", json_object_new_int64(0));
        json_object_object_add(tmp_obj, "used_kb", json_object_new_int64(0));
        json_object_object_add(storage_obj, "tmp", tmp_obj);
    }
    if (!json_object_object_get(storage_obj, "root")) {
        struct json_object *root_obj = json_object_new_object();
        json_object_object_add(root_obj, "total_kb", json_object_new_int64(0));
        json_object_object_add(root_obj, "used_kb", json_object_new_int64(0));
        json_object_object_add(storage_obj, "root", root_obj);
    }
    if (!json_object_object_get(storage_obj, "boot")) {
        struct json_object *boot_obj = json_object_new_object();
        json_object_object_add(boot_obj, "total_kb", json_object_new_int64(0));
        json_object_object_add(boot_obj, "used_kb", json_object_new_int64(0));
        json_object_object_add(storage_obj, "boot", boot_obj);
    }
    
    json_object_object_add(system_status, "storage", storage_obj);
    

    struct json_object *flow_obj = json_object_new_object();
    unsigned long long today_up = 0;
    unsigned long long today_down = 0;
    

    extern traffic_stat_t g_global_hourly_traffic[HOURS_PER_DAY];
    extern u_int32_t g_global_traffic_date;
    

    u_int32_t today = get_today_start_timestamp();
    if (g_global_traffic_date == today) {
        for (hour = 0; hour < HOURS_PER_DAY; hour++) {
            today_down += g_global_hourly_traffic[hour].down_bytes;
            today_up += g_global_hourly_traffic[hour].up_bytes;
        }
    } else {


        today_down = 0;
        today_up = 0;
    }
    

    today_down = today_down / 1024;
    today_up = today_up / 1024;
    
    json_object_object_add(flow_obj, "today_up", json_object_new_int64(today_up));
    json_object_object_add(flow_obj, "today_down", json_object_new_int64(today_down));
    json_object_object_add(system_status, "flow", flow_obj);


    int cpu_temp = get_cpu_temperature();
    if (cpu_temp > 0) {
        json_object_object_add(system_status, "cpu_temp", json_object_new_int(cpu_temp));
    }
    

    int wifi_temp = get_wifi_temperature();
    if (wifi_temp > 0) {
        json_object_object_add(system_status, "wifi_temp", json_object_new_int(wifi_temp));
    }
    
    return system_status;
}


static struct json_object *get_dashboard_network_status(void) {
    struct json_object *network_status = json_object_new_object();
    int work_mode = 0;
    if (jmx_work_mode_config_get(&work_mode, NULL, 0, NULL, 0) != 0)
        work_mode = 0;
    json_object_object_add(network_status, "work_mode", json_object_new_int(work_mode));
    
    json_object_object_add(network_status, "internet", json_object_new_int(g_jmx_status.internet));
    
    struct json_object *lan_obj = json_object_new_object();
    iface_status_t lan_status;
    memset(&lan_status, 0, sizeof(lan_status));
    
    if (get_iface_status("lan", &lan_status) == 0) {
        
	    json_object_object_add(lan_obj, "ip", json_object_new_string(strlen(lan_status.ip) > 0 ? lan_status.ip : ""));
	    json_object_object_add(lan_obj, "mask", json_object_new_string(strlen(lan_status.mask) > 0 ? lan_status.mask : ""));
	
	    json_object_object_add(lan_obj, "gateway", json_object_new_string(strlen(lan_status.gateway) > 0 ? lan_status.gateway : ""));

	    struct json_object *lan_dns = json_object_new_array();
	    if (strlen(lan_status.dns1) > 0) {
	        json_object_array_add(lan_dns, json_object_new_string(lan_status.dns1));
	    }
	    if (strlen(lan_status.dns2) > 0) {
	        json_object_array_add(lan_dns, json_object_new_string(lan_status.dns2));
	    }
	    json_object_object_add(lan_obj, "dns", lan_dns);
    }
    
    json_object_object_add(network_status, "lan", lan_obj);
    
    struct json_object *wan_obj = json_object_new_object();
    iface_status_t wan_status;
    memset(&wan_status, 0, sizeof(wan_status));
	
    if (get_iface_status("wan", &wan_status) == 0){
	    json_object_object_add(wan_obj, "ip", json_object_new_string(wan_status.ip));
	    json_object_object_add(wan_obj, "mask", json_object_new_string(wan_status.mask));
	    json_object_object_add(wan_obj, "gateway", json_object_new_string(wan_status.gateway));
	    struct json_object *wan_dns = json_object_new_array();
	    if (strlen(wan_status.dns1) > 0) {
	        json_object_array_add(wan_dns, json_object_new_string(wan_status.dns1));
	    }
	    if (strlen(wan_status.dns2) > 0) {
	        json_object_array_add(wan_dns, json_object_new_string(wan_status.dns2));
	    }
		
		json_object_object_add(wan_obj, "dns", wan_dns);
    }
    json_object_object_add(network_status, "wan", wan_obj);
    
    return network_status;
}



#define ICON_BASE_URL "/static/images/logo/"
#define ICON_BASE_DIR "/www/dreamingwrt/static/images/logo/"
#define SIGNATURE_APP_CACHE_MAX 512

typedef struct {
    unsigned int app_id;
    int valid;
    char name[128];
    char icon[256];
} signature_app_cache_entry_t;

static signature_app_cache_entry_t g_signature_app_cache[SIGNATURE_APP_CACHE_MAX];
static time_t g_signature_app_cache_mtime;
static off_t g_signature_app_cache_size;
static ino_t g_signature_app_cache_inode;

static int signature_app_db_path(char *path, size_t path_len)
{
    enum jmx_system_db_source source;
    char error[64];

    return jmx_system_db_resolve(JMX_SYSTEM_DB_SIGNATURE, path, path_len,
                                 &source, error, sizeof(error));
}

static const char *lookup_signature_app(unsigned int app_id, char *name, size_t name_len,
                                        char *icon, size_t icon_len)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *st = NULL;
    struct stat db_stat;
    char db_path[512];
    unsigned int slot = app_id % SIGNATURE_APP_CACHE_MAX;

    if (signature_app_db_path(db_path, sizeof(db_path)) != 0)
        return NULL;
    signature_app_cache_entry_t *entry = &g_signature_app_cache[slot];
    const char *icon_file = NULL;

    if (name && name_len)
        name[0] = '\0';
    if (icon && icon_len)
        icon[0] = '\0';
    if (app_id == 0)
        return NULL;
    if (stat(db_path, &db_stat) != 0) {
        memset(g_signature_app_cache, 0, sizeof(g_signature_app_cache));
        g_signature_app_cache_mtime = 0;
        g_signature_app_cache_size = 0;
        g_signature_app_cache_inode = 0;
        return NULL;
    }
    if (db_stat.st_mtime != g_signature_app_cache_mtime ||
        db_stat.st_size != g_signature_app_cache_size ||
        db_stat.st_ino != g_signature_app_cache_inode) {
        memset(g_signature_app_cache, 0, sizeof(g_signature_app_cache));
        g_signature_app_cache_mtime = db_stat.st_mtime;
        g_signature_app_cache_size = db_stat.st_size;
        g_signature_app_cache_inode = db_stat.st_ino;
    }
    if (entry->valid && entry->app_id == app_id) {
        if (name && name_len)
            snprintf(name, name_len, "%s", entry->name);
        if (icon && icon_len)
            snprintf(icon, icon_len, "%s", entry->icon);
        return entry->name[0] ? entry->name : NULL;
    }
    if (jmx_signature_db_open(&db) != 0)
        return NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT COALESCE(a.name,''),COALESCE(ia.icon_file,'') "
            "FROM app a LEFT JOIN app_icon ai ON ai.app_id=a.app_id "
            "LEFT JOIN icon_asset ia ON ia.icon_key=ai.icon_key "
            "WHERE a.app_id=?1 AND a.enabled=1 LIMIT 1",
            -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_int64(st, 1, app_id);
        if (sqlite3_step(st) == SQLITE_ROW) {
            const char *app_name = (const char *)sqlite3_column_text(st, 0);

            icon_file = (const char *)sqlite3_column_text(st, 1);
            memset(entry, 0, sizeof(*entry));
            entry->app_id = app_id;
            entry->valid = 1;
            snprintf(entry->name, sizeof(entry->name), "%s", app_name ? app_name : "");
            if (icon_file && !strncmp(icon_file, "icons/", 6))
                icon_file += 6;
            if (icon_file && icon_file[0] && !strstr(icon_file, "..") &&
                !strchr(icon_file, '/')) {
                char icon_path[PATH_MAX];

                if (snprintf(icon_path, sizeof(icon_path), "%s%s",
                             ICON_BASE_DIR, icon_file) < (int)sizeof(icon_path) &&
                    access(icon_path, R_OK) == 0)
                    snprintf(entry->icon, sizeof(entry->icon), "%s%s",
                             ICON_BASE_URL, icon_file);
            }
        }
    }
    if (st)
        sqlite3_finalize(st);
    jmx_signature_db_close(db);
    if (!entry->valid || entry->app_id != app_id)
        return NULL;
    if (name && name_len)
        snprintf(name, name_len, "%s", entry->name);
    if (icon && icon_len)
        snprintf(icon, icon_len, "%s", entry->icon);
    return entry->name[0] ? entry->name : NULL;
}

static const char *get_app_icon(unsigned int app_id)
{
    static char icon_path[256];

    if (lookup_signature_app(app_id, NULL, 0, icon_path, sizeof(icon_path)) == NULL)
        icon_path[0] = '\0';
    return icon_path;
}

static struct json_object *get_dashboard_active_app(void) {
    struct json_object *active_app = json_object_new_object();
    struct json_object *app_list = json_object_new_array();
    
    FILE *fp = jmx_fopen_af("af_active_app", "r");
    if (!fp) {

        json_object_object_add(active_app, "total", json_object_new_int(0));
        json_object_object_add(active_app, "list", app_list);
        return active_app;
    }
    
    char line[1024] = {0};
    int line_count = 0;
    int total_count = 0;
    

    while (fgets(line, sizeof(line), fp)) {

        if (line_count == 0) {
            line_count++;
            continue;
        }
        

        str_trim(line);
        if (strlen(line) == 0) {
            continue;
        }
        



        unsigned int app_id;
        char mac[32] = {0};
        char src_ip[64] = {0};
        unsigned int src_port;
        char dst_ip[64] = {0};
        unsigned int dst_port;
        char proto[8] = {0};
        unsigned int app_proto;
        unsigned int drop;
        char host[256] = {0};
        unsigned int last_update;
        char uri[256] = {0};
        u_int32_t current_time = get_timestamp();


        int parsed = sscanf(line, "%u %31s %63s %u %63s %u %7s %u %u %255s %u %255s",
                           &app_id, mac, src_ip, &src_port, dst_ip, &dst_port,
                           proto, &app_proto, &drop, host, &last_update, uri);        

        if (parsed < 11) {
            continue;
        }
        if (current_time > last_update && (current_time - last_update) > 180) {
                continue;
        }

        if (parsed < 12) {
            uri[0] = '\0';
        }
        

        str_trim(host);
        str_trim(uri);
        

        struct json_object *app = json_object_new_object();
        json_object_object_add(app, "id", json_object_new_int(app_id));
        

json_object_object_add(app, "name",
    json_object_new_string(jmx_safe_app_name(app_id)));
        json_object_object_add(app, "icon",
            json_object_new_string(get_app_icon(app_id)));
        

        json_object_object_add(app, "mac", json_object_new_string(mac));
        

        json_object_object_add(app, "src_ip", json_object_new_string(src_ip));
        json_object_object_add(app, "dst_ip", json_object_new_string(dst_ip));
        

        json_object_object_add(app, "src_port", json_object_new_int(src_port));
        json_object_object_add(app, "dst_port", json_object_new_int(dst_port));
        

        json_object_object_add(app, "protocol", json_object_new_string(proto));
        

        json_object_object_add(app, "app_proto", json_object_new_int(app_proto));
        

        json_object_object_add(app, "drop", json_object_new_int(drop));
        

        if (host[0] != '\0' && strcmp(host, "-") != 0) {
            json_object_object_add(app, "domain", json_object_new_string(host));
        } else {
            json_object_object_add(app, "domain", json_object_new_string(""));
        }
        

        if (app_proto == 1 && uri[0] != '\0' && strcmp(uri, "-") != 0) {
            json_object_object_add(app, "uri", json_object_new_string(uri));
        } else {
            json_object_object_add(app, "uri", json_object_new_string(""));
        }
        

        json_object_object_add(app, "timestamp", json_object_new_int(last_update));
        
        json_object_array_add(app_list, app);
        total_count++;
    }
    
    fclose(fp);
    
    json_object_object_add(active_app, "total", json_object_new_int(total_count));
    json_object_object_add(active_app, "list", app_list);
    
    return active_app;
}


static int compare_host_timestamp(const void *a, const void *b) {
    struct json_object *obj_a = *(struct json_object **)a;
    struct json_object *obj_b = *(struct json_object **)b;
    
    struct json_object *ts_a, *ts_b;
    json_object_object_get_ex(obj_a, "timestamp", &ts_a);
    json_object_object_get_ex(obj_b, "timestamp", &ts_b);
    
    int ts_val_a = ts_a ? json_object_get_int(ts_a) : 0;
    int ts_val_b = ts_b ? json_object_get_int(ts_b) : 0;
    
    return ts_val_b - ts_val_a;  // 降序排序
}


static struct json_object *get_dashboard_active_host(void) {
    struct json_object *active_host = json_object_new_object();
    struct json_object *host_list = json_object_new_array();
    int i;
    FILE *fp = jmx_fopen_af("af_active_host", "r");
    if (!fp) {

        json_object_object_add(active_host, "total", json_object_new_int(0));
        json_object_object_add(active_host, "list", host_list);
        return active_host;
    }
    
    char line[1024] = {0};
    int line_count = 0;
    int total_count = 0;
    

    while (fgets(line, sizeof(line), fp)) {

        if (line_count == 0) {
            line_count++;
            continue;
        }
        

        str_trim(line);
        if (strlen(line) == 0) {
            continue;
        }
        


char host_buf[256] = {0};
char mac[32] = {0};
char src_ip[64] = {0};
unsigned int src_port;
char dst_ip[64] = {0};
unsigned int dst_port;
char proto[8] = {0};
unsigned int app_proto;
unsigned int drop;
unsigned int last_update;
        

int parsed = sscanf(line, "%255s %31s %63s %u %63s %u %7s %u %u %u",
                   host_buf, mac, src_ip, &src_port, dst_ip, &dst_port,
                   proto, &app_proto, &drop, &last_update);
        

        if (parsed < 10) {
            continue; // 跳过无法解析的行
        }
        

        time_t current_time = time(NULL);
        if (current_time > last_update && (current_time - last_update) > 180) {
            continue; // 跳过超时的记录（3分钟 = 180秒）
        }
        

        str_trim(host_buf);
        

        if (host_buf[0] == '\0' || strcmp(host_buf, "-") == 0) {
            continue;
        }
        

        struct json_object *host_obj = json_object_new_object();
        

        json_object_object_add(host_obj, "mac", json_object_new_string(mac));
        

        extern struct list_head client_list;
        client_node_t *client = find_client_node(mac);
        

        char display_name[128] = {0};
        if (client && client->nickname[0] != '\0') {
            strncpy(display_name, client->nickname, sizeof(display_name) - 1);
        } else if (client && client->hostname[0] != '\0') {
            strncpy(display_name, client->hostname, sizeof(display_name) - 1);
        } else {
            strncpy(display_name, mac, sizeof(display_name) - 1);
        }
        json_object_object_add(host_obj, "name", json_object_new_string(display_name));
        

        if (client) {
            json_object_object_add(host_obj, "hostname", json_object_new_string(client->hostname[0] ? client->hostname : ""));
            json_object_object_add(host_obj, "nickname", json_object_new_string(client->nickname[0] ? client->nickname : ""));
        } else {
            json_object_object_add(host_obj, "hostname", json_object_new_string(""));
            json_object_object_add(host_obj, "nickname", json_object_new_string(""));
        }
        

        char url[sizeof(host_buf) + sizeof("https://")] = {0};
        if (app_proto == 1) {  
            snprintf(url, sizeof(url), "http://%s", host_buf);
        } else if (app_proto == 2) {  
            snprintf(url, sizeof(url), "https://%s", host_buf);
        } else {

            strncpy(url, host_buf, sizeof(url) - 1);
        }
        json_object_object_add(host_obj, "url", json_object_new_string(url));
        json_object_object_add(host_obj, "host", json_object_new_string(host_buf));
        

        json_object_object_add(host_obj, "app_proto", json_object_new_int(app_proto));
        


        json_object_object_add(host_obj, "timestamp", json_object_new_int(last_update));
        
        json_object_array_add(host_list, host_obj);
        total_count++;
    }
    
    fclose(fp);
    

    if (total_count > 0) {
        json_object_array_sort(host_list, compare_host_timestamp);
    }
    

    #define MAX_HOST_LIST_SIZE 10
    int array_len = json_object_array_length(host_list);
    if (array_len > MAX_HOST_LIST_SIZE) {

        for (i = array_len - 1; i >= MAX_HOST_LIST_SIZE; i--) {
            json_object_array_del_idx(host_list, i, 1);
        }
    }
    
    json_object_object_add(active_host, "total", json_object_new_int(total_count));
    json_object_object_add(active_host, "list", host_list);
    
    return active_host;
}



static int get_interface_device(const char *interface_name, char *device_name, size_t device_name_len) {
    struct uci_context *uci_ctx = uci_alloc_context();
    if (!uci_ctx) {
        LOG_ERROR("get_interface_device: failed to allocate UCI context\n");
        return -1;
    }
    
    char uci_key[128] = {0};
    snprintf(uci_key, sizeof(uci_key), "network.%s.device", interface_name);
    
    int ret = jmx_uci_get_value(uci_ctx, uci_key, device_name, device_name_len);
    uci_free_context(uci_ctx);
    
    if (ret != 0) {
        LOG_ERROR("get_interface_device: failed to get device for interface %s\n", interface_name);
        return -1;
    }
    
    return 0;
}


static int read_interface_traffic(const char *ifname, unsigned long long *up_bytes, unsigned long long *down_bytes) {
    FILE *netdev_fp = jmx_fopen_af("dev", "r");
    if (!netdev_fp) {
        LOG_ERROR("read_interface_traffic: failed to open /proc/net/dev\n");
        return -1;
    }
    
    char line[512];
    int found = 0;
    

    fgets(line, sizeof(line), netdev_fp);
    fgets(line, sizeof(line), netdev_fp);
    
    while (fgets(line, sizeof(line), netdev_fp)) {
        char interface[32] = {0};
        unsigned long long rx_pkts, rx_errs, rx_drop, rx_fifo, rx_frame, rx_compressed, rx_multicast;
        unsigned long long rx_bytes = 0, tx_bytes = 0;
        

        char *colon = strchr(line, ':');
        if (colon) {
            int ifname_len = colon - line;
            if (ifname_len > 0 && ifname_len < sizeof(interface)) {
                strncpy(interface, line, ifname_len);
                interface[ifname_len] = '\0';
                str_trim(interface);
                

                if (sscanf(colon + 1, "%llu %llu %llu %llu %llu %llu %llu %llu %llu", 
                           &rx_bytes, &rx_pkts, &rx_errs, &rx_drop, &rx_fifo, &rx_frame, &rx_compressed, &rx_multicast, &tx_bytes) >= 9) {
                    if (strcmp(interface, ifname) == 0) {
                        *down_bytes = rx_bytes;  
                        *up_bytes = tx_bytes;    
                        found = 1;
                        break;
                    }
                }
            }
        }
    }
    
    fclose(netdev_fp);
    return found ? 0 : -1;
}


static void add_interface_traffic_point(unsigned long long up_bytes, unsigned long long down_bytes) {
    u_int32_t current_time = time(NULL);
    unsigned int up_rate = 0;
    unsigned int down_rate = 0;
    

    if (last_traffic_time > 0 && current_time > last_traffic_time) {
        unsigned long long up_diff = (up_bytes > last_up_bytes) ? (up_bytes - last_up_bytes) : 0;
        unsigned long long down_diff = (down_bytes > last_down_bytes) ? (down_bytes - last_down_bytes) : 0;
        unsigned int time_diff = current_time - last_traffic_time;
        
        if (time_diff > 0) {
            up_rate = (unsigned int)(up_diff / time_diff);
            down_rate = (unsigned int)(down_diff / time_diff);
        }
    }
    

    interface_traffic_node_t *node = (interface_traffic_node_t *)calloc(1, sizeof(interface_traffic_node_t));
    if (!node) {
        return;
    }
    
    node->up_bytes = up_bytes;
    node->down_bytes = down_bytes;
    node->up_rate = up_rate;
    node->down_rate = down_rate;
    node->timestamp = current_time;
    

    list_add(&node->list, &interface_traffic_list);
    interface_traffic_count++;
    

    if (interface_traffic_count > MAX_INTERFACE_TRAFFIC_POINTS) {
        interface_traffic_node_t *old_node = list_last_entry(&interface_traffic_list, interface_traffic_node_t, list);
        list_del(&old_node->list);
        free(old_node);
        interface_traffic_count--;
    }
    

    last_up_bytes = up_bytes;
    last_down_bytes = down_bytes;
    last_traffic_time = current_time;
    
    LOG_DEBUG("add_interface_traffic_point: up_rate=%u B/s, down_rate=%u B/s\n", up_rate, down_rate);
}

void check_and_update_monitor_device(void) {    
    jmx_legacy_settings_t settings;
    char wan_device_name[16] = {0};

    if (jmx_legacy_settings_get(&settings) != 0)
        return;
    if (settings.monitor_device[0]) {
        snprintf(g_interface_name, sizeof(g_interface_name), "%s", settings.monitor_device);
        return;
    }
    if (get_interface_device("wan", wan_device_name, sizeof(wan_device_name)) == 0 && wan_device_name[0])
        snprintf(g_interface_name, sizeof(g_interface_name), "%s", wan_device_name);
    else
        snprintf(g_interface_name, sizeof(g_interface_name), "%s", "br-lan");
    if (jmx_legacy_settings_set_dashboard(g_interface_name) != 0)
        LOG_ERROR("Failed to save dashboard monitor device to config.db\n");
}


void collect_interface_traffic_rate(void) {
    unsigned long long up_bytes = 0, down_bytes = 0;
    if (strlen(g_interface_name) == 0){
        check_and_update_monitor_device();
        if (strlen(g_interface_name) == 0) {
            return;
        }
    }

    if (read_interface_traffic(g_interface_name, &up_bytes, &down_bytes) == 0)
        add_interface_traffic_point(up_bytes, down_bytes);
}

static struct json_object *get_dashboard_interface_traffic(void) {
    struct json_object *interface_traffic = json_object_new_object();
    json_object_object_add(interface_traffic, "interface", json_object_new_string(g_interface_name));
    struct json_object *traffic_array = json_object_new_array();
    interface_traffic_node_t *node = NULL;
    list_for_each_entry_reverse(node, &interface_traffic_list, list) {
        struct json_object *traffic = json_object_new_object();
        json_object_object_add(traffic, "up", json_object_new_int64(node->up_rate));
        json_object_object_add(traffic, "down", json_object_new_int64(node->down_rate));
        json_object_array_add(traffic_array, traffic);
    }
    
    int current_count = interface_traffic_count;
    while (current_count < MAX_INTERFACE_TRAFFIC_POINTS) {
        struct json_object *traffic = json_object_new_object();
        json_object_object_add(traffic, "up", json_object_new_int64(0));
        json_object_object_add(traffic, "down", json_object_new_int64(0));
        json_object_array_add(traffic_array, traffic);
        current_count++;
    }
    
    json_object_object_add(interface_traffic, "traffic", traffic_array);
    
    return interface_traffic;
}


struct json_object *jmx_api_get_dashboard_common(struct json_object *req_obj) {
    struct json_object *data_obj = json_object_new_object();
    struct json_object *system_status = get_dashboard_system_status();
    struct json_object *network_status = get_dashboard_network_status();
    struct json_object *active_app = get_dashboard_active_app();
    struct json_object *active_host = get_dashboard_active_host();
    struct json_object *interface_traffic = get_dashboard_interface_traffic();
    
    json_object_object_add(data_obj, "system_status", system_status);
    json_object_object_add(data_obj, "network_status", network_status);
    json_object_object_add(data_obj, "active_app", active_app);
    json_object_object_add(data_obj, "active_host", active_host);
    json_object_object_add(data_obj, "interface_traffic", interface_traffic);
    
    return jmx_gen_api_response_data(API_CODE_SUCCESS, data_obj);
}


struct json_object *jmx_api_get_hourly_top_apps(struct json_object *req_obj) {
	int i;
    struct json_object *data_obj = json_object_new_object();
    
    if (!req_obj) {
        return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    
    struct json_object *mac_obj = json_object_object_get(req_obj, "mac");
    if (!mac_obj) {
        json_object_put(data_obj);
        return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    const char *mac = json_object_get_string(mac_obj);
    if (!mac) {
        json_object_put(data_obj);
        return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    struct json_object *date_obj = json_object_object_get(req_obj, "date");
    u_int32_t target_date = 0;
    int is_today = 1;
    u_int32_t today = get_today_start_timestamp();
    
    if (date_obj) {
        target_date = (u_int32_t)json_object_get_int64(date_obj);
        is_today = (target_date == today);
    } else {
        target_date = today;
    }
    
    
    client_node_t *client = find_client_node(mac);
    if (!client) {
        json_object_put(data_obj);
        return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    daily_hourly_stat_t *stat = NULL;
    
    if (is_today) {
        
        update_hourly_top_apps(client);
        stat = get_today_stat(client);
        if (!stat) {
            json_object_put(data_obj);
            return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
        }
    } else {
        
        char stats_dir[512] = {0};
        char mac_buf[MAX_MAC_LEN] = {0};
        strncpy(mac_buf, client->mac, sizeof(mac_buf) - 1);
        
        
        for (i = 0; mac_buf[i] != '\0'; i++) {
            if (mac_buf[i] == ':') {
                mac_buf[i] = '_';
            }
        }
        
        char date_str[32] = {0};
        time_t t = (time_t)target_date;
        struct tm *tm_info = localtime(&t);
        if (tm_info) {
            strftime(date_str, sizeof(date_str), "%Y-%m-%d", tm_info);
        } 
        snprintf(stats_dir, sizeof(stats_dir), "%s/%s/stats/hourly_%s.json", 
                 get_client_data_base_dir(), mac_buf, date_str);
 
        struct json_object *file_json = json_object_from_file(stats_dir);
        if (!file_json) {
            json_object_put(data_obj);
            return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
        }

        json_object_object_add(data_obj, "mac", json_object_new_string(client->mac));
        json_object_object_add(data_obj, "date", json_object_new_int64(target_date));
        json_object_object_add(data_obj, "is_today", json_object_new_int(0));
        
        struct json_object *hourly_stats = json_object_object_get(file_json, "hourly_stats");
        if (hourly_stats) {
            
            json_object_object_add(data_obj, "hourly_stats", hourly_stats);
        } else {
            json_object_object_add(data_obj, "hourly_stats", json_object_new_array());
        }
          
        json_object_put(file_json);
        return jmx_gen_api_response_data(API_CODE_SUCCESS, data_obj);
    }
    
    
    struct json_object *hourly_array = json_object_new_array();
    int hour;
    for (hour = 0; hour < HOURS_PER_DAY; hour++) {
        struct json_object *hour_obj = json_object_new_object();
        struct json_object *apps_array = json_object_new_array();
        
        json_object_object_add(hour_obj, "hour", json_object_new_int(hour));  
        for (i = 0; i < TOP_APP_PER_HOUR; i++) {
            if (stat->hourly_top_apps[hour][i] > 0) {
                struct json_object *app_obj = json_object_new_object();
                int appid = stat->hourly_top_apps[hour][i];
                json_object_object_add(app_obj, "appid", json_object_new_int(appid));
                const char *app_name = get_app_name_by_id(appid);
                if (app_name) {
                    json_object_object_add(app_obj, "name", json_object_new_string(app_name));
                } else {
                    json_object_object_add(app_obj, "name", json_object_new_string("unknown"));
                }
                
                
                unsigned long long app_time = 0;
                if (is_today && client) {
                    u_int32_t today_start = get_today_start_timestamp();
                    visit_info_t *p_info = NULL;
                    list_for_each_entry(p_info, &client->online_visit, visit) {
                        if (p_info->first_time < today_start)
                            continue;
                        
                        int visit_hour = get_hour_from_timestamp(p_info->first_time);
                        if (visit_hour == hour && p_info->appid == appid) {
                            unsigned long long visit_time = p_info->latest_time - p_info->first_time;
                            if (visit_time == 0)
                                visit_time = 1; 
                            app_time += visit_time;
                        }
                    }
                    list_for_each_entry(p_info, &client->visit, visit) {
                        
                        if (p_info->first_time < today_start)
                            continue;
                        
                        
                        int visit_hour = get_hour_from_timestamp(p_info->first_time);
                        if (visit_hour == hour && p_info->appid == appid) {
                            unsigned long long visit_time = p_info->latest_time - p_info->first_time;
                            if (visit_time == 0)
                                visit_time = 1; 
                            app_time += visit_time;
                        }
                    }
                }
                json_object_object_add(app_obj, "time", json_object_new_int64(app_time));
                
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
    
    json_object_object_add(data_obj, "mac", json_object_new_string(client->mac));
    json_object_object_add(data_obj, "date", json_object_new_int64(stat->date));
    json_object_object_add(data_obj, "is_today", json_object_new_int(stat->is_today));
    json_object_object_add(data_obj, "hourly_stats", hourly_array);
    
    return jmx_gen_api_response_data(API_CODE_SUCCESS, data_obj);
}


struct json_object *jmx_api_get_daily_top_apps(struct json_object *req_obj) {
    struct json_object *data_obj = json_object_new_object();
    int i;
    if (!req_obj) {
        return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
    }

    struct json_object *mac_obj = json_object_object_get(req_obj, "mac");
    if (!mac_obj) {
        json_object_put(data_obj);
        return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    const char *mac = json_object_get_string(mac_obj);
    if (!mac) {
        json_object_put(data_obj);
        return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    struct json_object *date_obj = json_object_object_get(req_obj, "date");
    u_int32_t target_date = 0;
    int is_today = 1;
    u_int32_t today = get_today_start_timestamp();
    
    if (date_obj) {
        target_date = (u_int32_t)json_object_get_int64(date_obj);
        is_today = (target_date == today);
    } else {
        target_date = today;
    }

    client_node_t *client = find_client_node(mac);
    if (!client) {
        json_object_put(data_obj);
        return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    daily_top_apps_stat_t *stat = NULL;
    
    if (is_today) {
        
        update_daily_top_apps(client);
        stat = get_today_top_apps_stat(client);
        if (!stat) {
            json_object_put(data_obj);
            return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
        }
        
        
        struct json_object *apps_array = json_object_new_array();
        
        for (i = 0; i < stat->count; i++) {
            struct json_object *app_obj = json_object_new_object();
            json_object_object_add(app_obj, "appid", json_object_new_int(stat->apps[i].appid));
            json_object_object_add(app_obj, "total_time", json_object_new_int64(stat->apps[i].total_time));
            const char *app_name = get_app_name_by_id(stat->apps[i].appid);
            if (app_name) {
                json_object_object_add(app_obj, "name", json_object_new_string(app_name));
            } else {
                json_object_object_add(app_obj, "name", json_object_new_string("unknown"));
            }
            json_object_array_add(apps_array, app_obj);
        }
        
        json_object_object_add(data_obj, "mac", json_object_new_string(client->mac));
        json_object_object_add(data_obj, "date", json_object_new_int64(stat->date));
        json_object_object_add(data_obj, "is_today", json_object_new_int(stat->is_today));
        json_object_object_add(data_obj, "count", json_object_new_int(stat->count));
        json_object_object_add(data_obj, "apps", apps_array);
    } else {
        
        char stats_dir[512] = {0};
        char mac_buf[64] = {0};
        strncpy(mac_buf, client->mac, sizeof(mac_buf) - 1);
        mac_buf[sizeof(mac_buf) - 1] = '\0';

        
        for (i = 0; mac_buf[i] != '\0'; i++) {
            if (mac_buf[i] == ':') {
                mac_buf[i] = '_';       
            }
        }
        
        char date_str[32] = {0};
        time_t t = (time_t)target_date;
        struct tm *tm_info = localtime(&t);
        if (tm_info) {
            strftime(date_str, sizeof(date_str), "%Y-%m-%d", tm_info);
        }
        
        snprintf(stats_dir, sizeof(stats_dir), "%s/%s/stats/top_apps_%s.json", 
                 get_client_data_base_dir(), mac_buf, date_str);
        
        
        struct json_object *file_json = json_object_from_file(stats_dir);
        if (!file_json) {
            json_object_put(data_obj);
            return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
        }
        
        
        struct json_object *mac_obj = json_object_object_get(file_json, "mac");
        struct json_object *date_obj = json_object_object_get(file_json, "date");
        struct json_object *count_obj = json_object_object_get(file_json, "count");
        struct json_object *apps_obj = json_object_object_get(file_json, "apps");
        
        if (mac_obj) {
            json_object_object_add(data_obj, "mac", mac_obj);
        } else {
            json_object_object_add(data_obj, "mac", json_object_new_string(client->mac));
        }
        
        if (date_obj) {
            json_object_object_add(data_obj, "date", date_obj);
        } else {
            json_object_object_add(data_obj, "date", json_object_new_int64(target_date));
        }
        
        json_object_object_add(data_obj, "is_today", json_object_new_int(0));
        
        if (count_obj) {
            json_object_object_add(data_obj, "count", count_obj);
        } else {
            json_object_object_add(data_obj, "count", json_object_new_int(0));
        }
        
        if (apps_obj) {
            json_object_object_add(data_obj, "apps", apps_obj);
        } else {
            json_object_object_add(data_obj, "apps", json_object_new_array());
        }
        
        
        json_object_put(file_json);
    }
    
    return jmx_gen_api_response_data(API_CODE_SUCCESS, data_obj);
}


struct json_object *jmx_api_delete_record_files(struct json_object *req_obj) {
    struct json_object *mac_obj = json_object_object_get(req_obj, "mac");
    struct json_object *start_date_obj = json_object_object_get(req_obj, "start_date");
    struct json_object *end_date_obj = json_object_object_get(req_obj, "end_date");
    struct json_object *type_obj = json_object_object_get(req_obj, "type");
    
    const char *mac = NULL;
    const char *start_date = NULL;
    const char *end_date = NULL;
    const char *delete_type = NULL;
    
    if (mac_obj) {
        mac = json_object_get_string(mac_obj);
    }
    if (start_date_obj) {
        start_date = json_object_get_string(start_date_obj);
    }
    if (end_date_obj) {
        end_date = json_object_get_string(end_date_obj);
    }
    if (type_obj) {
        delete_type = json_object_get_string(type_obj);
    }
    
    LOG_DEBUG("Delete record files: mac=%s, start_date=%s, end_date=%s, type=%s\n",
             mac ? mac : "all", 
             start_date ? start_date : "none",
             end_date ? end_date : "none",
             delete_type ? delete_type : "all");
    
    
    delete_client_record_files(mac, start_date, end_date, delete_type);
    
    struct json_object *data_obj = json_object_new_object();
    json_object_object_add(data_obj, "message", json_object_new_string("Delete request processed"));
    
    return jmx_gen_api_response_data(API_CODE_SUCCESS, data_obj);
}


typedef struct {
    int app_type;  
    unsigned long long total_time;  
} app_type_stat_sort_t;


static int compare_app_type_stat_sort(const void *a, const void *b) {
    app_type_stat_sort_t *pa = (app_type_stat_sort_t *)a;
    app_type_stat_sort_t *pb = (app_type_stat_sort_t *)b;
    if (pa->total_time > pb->total_time)
        return -1;
    if (pa->total_time < pb->total_time)
        return 1;
    return 0;
}


struct json_object *jmx_api_get_global_app_type_stats(struct json_object *req_obj) {
    struct json_object *type_obj = json_object_object_get(req_obj, "type");
    struct json_object *limit_obj = json_object_object_get(req_obj, "limit");
    int i;
    const char *stat_type = "daily";  
    int limit = 10;  
    
    if (type_obj) {
        stat_type = json_object_get_string(type_obj);
    }
    if (limit_obj) {
        limit = json_object_get_int(limit_obj);
        if (limit <= 0 || limit > MAX_APP_TYPE)
            limit = MAX_APP_TYPE;
    }
    
    unsigned long long type_time_array[MAX_APP_TYPE] = {0};
    
    
    if (stat_type && strcmp(stat_type, "hourly") == 0) {
        get_global_hourly_app_type_stats(type_time_array);
    } else {
        get_global_daily_app_type_stats(type_time_array);
    }
    
    
    app_type_stat_sort_t stats[MAX_APP_TYPE];
    int valid_count = 0;
    
    for (i = 0; i < MAX_APP_TYPE; i++) {
        if (type_time_array[i] > 0) {
            stats[valid_count].app_type = i + 1;  
            stats[valid_count].total_time = type_time_array[i];
            valid_count++;
        }
    }
    
    
    if (valid_count == 0) {
        for (i = 0; i < 5; i++) {
            stats[valid_count].app_type = i + 1;  
            stats[valid_count].total_time = 0;     
            valid_count++;
        }
    }
    
    
    if (valid_count > 0) {
        qsort(stats, valid_count, sizeof(app_type_stat_sort_t), compare_app_type_stat_sort);
    }
    
    
    struct json_object *data_obj = json_object_new_object();
    json_object_object_add(data_obj, "type", json_object_new_string(stat_type));
    json_object_object_add(data_obj, "limit", json_object_new_int(limit));
    json_object_object_add(data_obj, "total_count", json_object_new_int(valid_count));
    
    struct json_object *types_array = json_object_new_array();
    int return_count = (valid_count < limit) ? valid_count : limit;
    
    for (i = 0; i < return_count; i++) {
        struct json_object *type_obj = json_object_new_object();
        json_object_object_add(type_obj, "app_type", json_object_new_int(stats[i].app_type));
        json_object_object_add(type_obj, "total_time", json_object_new_int64(stats[i].total_time));
        
        
int type_index = stats[i].app_type - 1;
const char *type_name = jmx_safe_class_name(type_index);

if (!type_name || strcmp(type_name, "unknown") == 0) {
    static char default_name[32] = {0};
    snprintf(default_name, sizeof(default_name), "分类%d", stats[i].app_type);
    type_name = default_name;
}

json_object_object_add(type_obj, "name", json_object_new_string(type_name));
        
        json_object_array_add(types_array, type_obj);
    }
    
    json_object_object_add(data_obj, "types", types_array);
    
    return jmx_gen_api_response_data(API_CODE_SUCCESS, data_obj);
}


struct json_object *jmx_api_get_global_traffic_stats(struct json_object *req_obj) {
    struct json_object *date_obj = json_object_object_get(req_obj, "date");
    int hour;
    u_int32_t target_date = 0;
    int is_today = 1;
    u_int32_t today = get_today_start_timestamp();
    
    if (date_obj) {
        target_date = (u_int32_t)json_object_get_int64(date_obj);
        is_today = (target_date == today);
    } else {
        target_date = today;
    }
    
    struct json_object *data_obj = json_object_new_object();
    
    if (is_today) {
        
        traffic_stat_t traffic_array[HOURS_PER_DAY];
        get_global_traffic_stats(traffic_array);
        
        json_object_object_add(data_obj, "date", json_object_new_int64(today));
        json_object_object_add(data_obj, "is_today", json_object_new_int(1));
        
        struct json_object *hourly_array = json_object_new_array();
        for (hour = 0; hour < HOURS_PER_DAY; hour++) {
            struct json_object *hour_obj = json_object_new_object();
            json_object_object_add(hour_obj, "hour", json_object_new_int(hour));
            
            struct json_object *traffic_obj = json_object_new_object();
            json_object_object_add(traffic_obj, "up_bytes", json_object_new_int64(traffic_array[hour].up_bytes));
            json_object_object_add(traffic_obj, "down_bytes", json_object_new_int64(traffic_array[hour].down_bytes));
            json_object_object_add(hour_obj, "traffic", traffic_obj);
            
            json_object_array_add(hourly_array, hour_obj);
        }
        
        json_object_object_add(data_obj, "hourly_traffic", hourly_array);
    } else {
        
        char date_str[32] = {0};
        time_t t = (time_t)target_date;
        struct tm *tm_info = localtime(&t);
        if (tm_info) {
            strftime(date_str, sizeof(date_str), "%Y-%m-%d", tm_info);
        }
        
        char file_path[512] = {0};
        snprintf(file_path, sizeof(file_path), "%s/global/stats/traffic_%s.json", get_client_data_base_dir(), date_str);
        
        
        struct json_object *file_json = json_object_from_file(file_path);
        if (!file_json) {
            json_object_put(data_obj);
            return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
        }
        
        
        json_object_object_add(data_obj, "date", json_object_new_int64(target_date));
        json_object_object_add(data_obj, "is_today", json_object_new_int(0));
        
        struct json_object *hourly_traffic = json_object_object_get(file_json, "hourly_traffic");
        if (hourly_traffic) {
            json_object_object_add(data_obj, "hourly_traffic", hourly_traffic);
        } else {
            json_object_object_add(data_obj, "hourly_traffic", json_object_new_array());
        }
        
        json_object_put(file_json);
    }
    
    return jmx_gen_api_response_data(API_CODE_SUCCESS, data_obj);
}


typedef struct user_traffic_sort {
    char mac[MAX_MAC_LEN];
    char ip[MAX_IP_LEN];
    char hostname[MAX_HOSTNAME_SIZE];
    char nickname[MAX_NICKNAME_SIZE];
    unsigned long long up_bytes;
    unsigned long long down_bytes;
    unsigned long long total_bytes;  
} user_traffic_sort_t;


static int compare_user_traffic(const void *a, const void *b) {
    const user_traffic_sort_t *ua = (const user_traffic_sort_t *)a;
    const user_traffic_sort_t *ub = (const user_traffic_sort_t *)b;
    
    if (ua->total_bytes > ub->total_bytes) {
        return -1;
    } else if (ua->total_bytes < ub->total_bytes) {
        return 1;
    }
    return 0;
}


struct json_object *jmx_api_get_daily_top_users(struct json_object *req_obj) {
	int i;
	int hour;
    LOG_DEBUG("jmx_api_get_daily_top_users: called\n");
    
    struct json_object *data_obj = json_object_new_object();
    if (!data_obj) {
        LOG_ERROR("jmx_api_get_daily_top_users: failed to create data_obj\n");
        return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    
    u_int32_t today = get_today_start_timestamp();
    LOG_DEBUG("jmx_api_get_daily_top_users: today timestamp = %u\n", today);
    
    
    user_traffic_sort_t user_traffic_list[1024];  
    int user_count = 0;
    
    LOG_DEBUG("jmx_api_get_daily_top_users: start iterating client_list\n");
    client_node_t *node = NULL;
    list_for_each_entry(node, &client_list, client) {
        if (user_count >= 1024) {
            LOG_ERROR("jmx_api_get_daily_top_users: user_count reached max limit 1024\n");
            break;  
        }
        
        
        daily_hourly_stat_t *today_stat = get_today_stat(node);
        if (!today_stat) {
            LOG_DEBUG("jmx_api_get_daily_top_users: client %s has no today_stat, skip\n", node->mac);
            continue;
        }
        
        
        unsigned long long up_bytes = 0;
        unsigned long long down_bytes = 0;
        
        for (hour = 0; hour < HOURS_PER_DAY; hour++) {
            up_bytes += today_stat->hourly_traffic[hour].up_bytes;
            down_bytes += today_stat->hourly_traffic[hour].down_bytes;
        }
        
        LOG_DEBUG("jmx_api_get_daily_top_users: client %s, up_bytes=%llu, down_bytes=%llu\n", 
                 node->mac, up_bytes, down_bytes);
        
        
        if (up_bytes > 0 || down_bytes > 0) {
            user_traffic_sort_t *user = &user_traffic_list[user_count];
            
            strncpy(user->mac, node->mac, sizeof(user->mac) - 1);
            user->mac[sizeof(user->mac) - 1] = '\0';
            
            strncpy(user->ip, node->ip, sizeof(user->ip) - 1);
            user->ip[sizeof(user->ip) - 1] = '\0';
            
            strncpy(user->hostname, node->hostname, sizeof(user->hostname) - 1);
            user->hostname[sizeof(user->hostname) - 1] = '\0';
            
            strncpy(user->nickname, node->nickname, sizeof(user->nickname) - 1);
            user->nickname[sizeof(user->nickname) - 1] = '\0';
            
            user->up_bytes = up_bytes;
            user->down_bytes = down_bytes;
            user->total_bytes = up_bytes + down_bytes;
            
            LOG_DEBUG("jmx_api_get_daily_top_users: added user %s (mac=%s, total_bytes=%llu)\n", 
                     user->nickname[0] ? user->nickname : (user->hostname[0] ? user->hostname : user->mac),
                     user->mac, user->total_bytes);
            
            user_count++;
        }
    }
    
    LOG_DEBUG("jmx_api_get_daily_top_users: total user_count = %d\n", user_count);
    
    
    if (user_count > 0) {
        LOG_DEBUG("jmx_api_get_daily_top_users: sorting %d users\n", user_count);
        qsort(user_traffic_list, user_count, sizeof(user_traffic_sort_t), compare_user_traffic);
    }
    
    
    int return_count = (user_count < 8) ? user_count : 8;
    LOG_DEBUG("jmx_api_get_daily_top_users: return_count = %d\n", return_count);
    
    
    json_object_object_add(data_obj, "date", json_object_new_int64(today));
    json_object_object_add(data_obj, "total_count", json_object_new_int(user_count));
    
    struct json_object *users_array = json_object_new_array();
    if (!users_array) {
        LOG_ERROR("jmx_api_get_daily_top_users: failed to create users_array\n");
        json_object_put(data_obj);
        return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    for (i = 0; i < return_count; i++) {
        struct json_object *user_obj = json_object_new_object();
        if (!user_obj) {
            LOG_ERROR("jmx_api_get_daily_top_users: failed to create user_obj[%d]\n", i);
            continue;
        }
        
        json_object_object_add(user_obj, "mac", json_object_new_string(user_traffic_list[i].mac));
        json_object_object_add(user_obj, "ip", json_object_new_string(user_traffic_list[i].ip));
        json_object_object_add(user_obj, "hostname", json_object_new_string(user_traffic_list[i].hostname));
        json_object_object_add(user_obj, "nickname", json_object_new_string(user_traffic_list[i].nickname));
        json_object_object_add(user_obj, "up_bytes", json_object_new_int64(user_traffic_list[i].up_bytes));
        json_object_object_add(user_obj, "down_bytes", json_object_new_int64(user_traffic_list[i].down_bytes));
        json_object_object_add(user_obj, "total_bytes", json_object_new_int64(user_traffic_list[i].total_bytes));
        
        json_object_array_add(users_array, user_obj);
        
        LOG_DEBUG("jmx_api_get_daily_top_users: added user[%d]: mac=%s, total_bytes=%llu\n", 
                 i, user_traffic_list[i].mac, user_traffic_list[i].total_bytes);
    }
    
    json_object_object_add(data_obj, "users", users_array);
    
    LOG_DEBUG("jmx_api_get_daily_top_users: success, returning %d users\n", return_count);
    return jmx_gen_api_response_data(API_CODE_SUCCESS, data_obj);
}


typedef struct active_user_sort {
    char mac[MAX_MAC_LEN];
    char ip[MAX_IP_LEN];
    char hostname[MAX_HOSTNAME_SIZE];
    char nickname[MAX_NICKNAME_SIZE];
    unsigned int up_rate;  
    unsigned int down_rate;  
    unsigned long long today_up_bytes;  
    unsigned long long today_down_bytes;  
    int visiting_app;  
    char visiting_url[MAX_REPORT_URL_LEN];  
    unsigned int total_rate;  
    int active;  
    u_int32_t online_duration;  
    u_int32_t last_update_time;  
} active_user_sort_t;


static int compare_active_users(const void *a, const void *b) {
    const active_user_sort_t *user_a = (const active_user_sort_t *)a;
    const active_user_sort_t *user_b = (const active_user_sort_t *)b;
    
    
    if (user_b->total_rate > user_a->total_rate)
        return 1;
    else if (user_b->total_rate < user_a->total_rate)
        return -1;
    
    
    if (user_b->active > user_a->active)
        return 1;
    else if (user_b->active < user_a->active)
        return -1;
    
    
    int user_a_visiting = (user_a->visiting_app > 0 || strlen(user_a->visiting_url) > 0) ? 1 : 0;
    int user_b_visiting = (user_b->visiting_app > 0 || strlen(user_b->visiting_url) > 0) ? 1 : 0;
    if (user_b_visiting > user_a_visiting)
        return 1;
    else if (user_b_visiting < user_a_visiting)
        return -1;
    
    
    if (user_b->online_duration > user_a->online_duration)
        return 1;
    else if (user_b->online_duration < user_a->online_duration)
        return -1;
    
    
    if (user_b->last_update_time > user_a->last_update_time)
        return 1;
    else if (user_b->last_update_time < user_a->last_update_time)
        return -1;
    
    return 0;
}


struct json_object *jmx_api_get_active_users(struct json_object *req_obj) {
	int i;
	int hour;
    struct json_object *data_obj = json_object_new_object();
    if (!data_obj) {
        LOG_ERROR("jmx_api_get_active_users: failed to create data_obj\n");
        return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    
    int count = 10;
    if (req_obj) {
        struct json_object *count_obj = json_object_object_get(req_obj, "count");
        if (count_obj) {
            count = json_object_get_int(count_obj);
            if (count <= 0 || count > 100) {
                count = 10;  
            }
        }
    }
    
    LOG_DEBUG("jmx_api_get_active_users: start, count=%d\n", count);
    
    
    update_client_nickname();
    update_client_visiting_info();
    
    active_user_sort_t active_user_list[1024];  
    int user_count = 0;
    
    client_node_t *node = NULL;
    list_for_each_entry(node, &client_list, client) {
        if (user_count >= 1024) {
            LOG_ERROR("jmx_api_get_active_users: user_count reached max limit 1024\n");
            break;
        }
        
        
        if (!node->online) {
            continue;
        }
        LOG_DEBUG("mac = %s, online = %d\n", node->mac, node->online);
        
        
        unsigned int total_rate = node->up_rate + node->down_rate;

        active_user_sort_t *user = &active_user_list[user_count];
        
        strncpy(user->mac, node->mac, sizeof(user->mac) - 1);
        user->mac[sizeof(user->mac) - 1] = '\0';
        
        strncpy(user->ip, node->ip, sizeof(user->ip) - 1);
        user->ip[sizeof(user->ip) - 1] = '\0';
        
        strncpy(user->hostname, node->hostname, sizeof(user->hostname) - 1);
        user->hostname[sizeof(user->hostname) - 1] = '\0';
        
        strncpy(user->nickname, node->nickname, sizeof(user->nickname) - 1);
        user->nickname[sizeof(user->nickname) - 1] = '\0';
        
        user->up_rate = node->up_rate;
        user->down_rate = node->down_rate;
        user->total_rate = total_rate;
        user->active = node->active;  
        user->visiting_app = node->visiting_app;
        
        strncpy(user->visiting_url, node->visiting_url, sizeof(user->visiting_url) - 1);
        user->visiting_url[sizeof(user->visiting_url) - 1] = '\0';
        
        
        u_int32_t current_time = get_timestamp();
        if (node->online_time > 0) {
            user->online_duration = current_time - node->online_time;  
            user->last_update_time = node->online_time;  
        } else {
            user->online_duration = 0;
            user->last_update_time = 0;
        }
        
        
        daily_hourly_stat_t *today_stat = get_today_stat(node);
        unsigned long long today_up_bytes = 0;
        unsigned long long today_down_bytes = 0;
        
        if (today_stat) {
            for (hour = 0; hour < HOURS_PER_DAY; hour++) {
                today_up_bytes += today_stat->hourly_traffic[hour].up_bytes;
                today_down_bytes += today_stat->hourly_traffic[hour].down_bytes;
            }
        }
        
        user->today_up_bytes = today_up_bytes;
        user->today_down_bytes = today_down_bytes;
        
        user_count++;
        
        LOG_DEBUG("jmx_api_get_active_users: added user: mac=%s, total_rate=%u\n", 
                    user->mac, user->total_rate);
        
    }
    
    
    if (user_count > 0) {
        LOG_DEBUG("jmx_api_get_active_users: sorting %d users\n", user_count);
        qsort(active_user_list, user_count, sizeof(active_user_sort_t), compare_active_users);
    }
    
    
    int return_count = (user_count < count) ? user_count : count;
    LOG_DEBUG("jmx_api_get_active_users: return_count = %d\n", return_count);
    
    
    json_object_object_add(data_obj, "total_count", json_object_new_int(user_count));
    
    struct json_object *users_array = json_object_new_array();
    if (!users_array) {
        LOG_ERROR("jmx_api_get_active_users: failed to create users_array\n");
        json_object_put(data_obj);
        return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    for (i = 0; i < return_count; i++) {
        struct json_object *user_obj = json_object_new_object();
        if (!user_obj) {
            LOG_ERROR("jmx_api_get_active_users: failed to create user_obj[%d]\n", i);
            continue;
        }
        
        json_object_object_add(user_obj, "mac", json_object_new_string(active_user_list[i].mac));
        json_object_object_add(user_obj, "ip", json_object_new_string(active_user_list[i].ip));
        json_object_object_add(user_obj, "hostname", json_object_new_string(active_user_list[i].hostname));
        json_object_object_add(user_obj, "nickname", json_object_new_string(active_user_list[i].nickname));
        json_object_object_add(user_obj, "up_rate", json_object_new_int(active_user_list[i].up_rate));
        json_object_object_add(user_obj, "down_rate", json_object_new_int(active_user_list[i].down_rate));
        json_object_object_add(user_obj, "today_up_bytes", json_object_new_int64(active_user_list[i].today_up_bytes));
        json_object_object_add(user_obj, "today_down_bytes", json_object_new_int64(active_user_list[i].today_down_bytes));
        
        
        if (active_user_list[i].visiting_app > 0) {
            json_object_object_add(user_obj, "app", json_object_new_string(get_app_name_by_id(active_user_list[i].visiting_app)));
        } else {
            json_object_object_add(user_obj, "app", json_object_new_string(""));
        }
        
        if (strlen(active_user_list[i].visiting_url) > 0) {
            json_object_object_add(user_obj, "url", json_object_new_string(active_user_list[i].visiting_url));
        } else {
            json_object_object_add(user_obj, "url", json_object_new_string(""));
        }
        
        json_object_array_add(users_array, user_obj);
        
        LOG_DEBUG("jmx_api_get_active_users: added user[%d]: mac=%s, total_rate=%u\n", 
                 i, active_user_list[i].mac, active_user_list[i].total_rate);
    }
    
    json_object_object_add(data_obj, "users", users_array);
    LOG_DEBUG("data_obj: %s\n", json_object_to_json_string(data_obj));
    
    LOG_DEBUG("jmx_api_get_active_users: success, returning %d users\n", return_count);
    return jmx_gen_api_response_data(API_CODE_SUCCESS, data_obj);
}


struct json_object *jmx_api_get_user_basic_info(struct json_object *req_obj) {
    struct json_object *data_obj = json_object_new_object();
    int hour;
    if (!req_obj) {
        return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    

    struct json_object *mac_obj = json_object_object_get(req_obj, "mac");
    if (!mac_obj) {
        json_object_put(data_obj);
        return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    const char *target_mac = json_object_get_string(mac_obj);
    if (!target_mac) {
        json_object_put(data_obj);
        return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    update_client_nickname();
    update_client_visiting_info();
    
    extern struct list_head client_list;
    client_node_t *client = NULL;
    

    list_for_each_entry(client, &client_list, client) {
        if (strcmp(client->mac, target_mac) == 0) {

            json_object_object_add(data_obj, "mac", json_object_new_string(client->mac));
            json_object_object_add(data_obj, "ip", json_object_new_string(client->ip));
            json_object_object_add(data_obj, "ipv6", json_object_new_string(client->ipv6));
            json_object_object_add(data_obj, "nickname", json_object_new_string(client->nickname));
            json_object_object_add(data_obj, "hostname", json_object_new_string(client->hostname));
            json_object_object_add(data_obj, "online", json_object_new_int(client->online));
            

            daily_hourly_stat_t *today_stat = get_today_stat(client);
            unsigned long long today_up_bytes = 0;
            unsigned long long today_down_bytes = 0;
            unsigned long long today_online_time = 0;
            unsigned long long today_active_time = 0;
            
            if (today_stat) {
                for (hour = 0; hour < HOURS_PER_DAY; hour++) {
                    today_up_bytes += today_stat->hourly_traffic[hour].up_bytes;
                    today_down_bytes += today_stat->hourly_traffic[hour].down_bytes;
                    today_online_time += today_stat->hourly_online_time[hour];
                    today_active_time += today_stat->hourly_active_time[hour];
                }
            }
            
            json_object_object_add(data_obj, "today_up_bytes", json_object_new_int64(today_up_bytes));
            json_object_object_add(data_obj, "today_down_bytes", json_object_new_int64(today_down_bytes));
            json_object_object_add(data_obj, "today_online_time", json_object_new_int64(today_online_time));
            json_object_object_add(data_obj, "today_active_time", json_object_new_int64(today_active_time));
            

            return jmx_gen_api_response_data(API_CODE_SUCCESS, data_obj);
        }
    }
    

    json_object_put(data_obj);
    return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
}


struct json_object *jmx_api_get_online_offline_records(struct json_object *req_obj) {
    struct json_object *data_obj = json_object_new_object();
    
    if (!req_obj) {
        return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    
    struct json_object *mac_obj = NULL;
    if (!json_object_object_get_ex(req_obj, "mac", &mac_obj) || !mac_obj) {
        LOG_ERROR("jmx_api_get_online_offline_records: missing mac parameter\n");
        json_object_put(data_obj);
        return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    const char *mac = json_object_get_string(mac_obj);
    if (!mac || strlen(mac) == 0) {
        LOG_ERROR("jmx_api_get_online_offline_records: invalid mac parameter\n");
        json_object_put(data_obj);
        return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    
    extern struct list_head client_list;
    client_node_t *client = find_client_node(mac);
    if (!client) {
        LOG_ERROR("jmx_api_get_online_offline_records: client not found for mac=%s\n", mac);
        json_object_put(data_obj);
        return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    
    struct json_object *records_array = json_object_new_array();
    if (!records_array) {
        LOG_ERROR("jmx_api_get_online_offline_records: failed to create records_array\n");
        json_object_put(data_obj);
        return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    
    online_offline_record_t *record = NULL;
    int record_count = 0;
    list_for_each_entry(record, &client->online_offline_records, record) {
        struct json_object *record_obj = json_object_new_object();
        if (!record_obj) {
            LOG_ERROR("jmx_api_get_online_offline_records: failed to create record_obj\n");
            continue;
        }
        
        json_object_object_add(record_obj, "type", json_object_new_int(record->type));
        json_object_object_add(record_obj, "timestamp", json_object_new_int64(record->timestamp));
        json_object_object_add(record_obj, "duration", json_object_new_int64(record->duration));
        
        
        char time_str[64] = {0};
        time_t t = (time_t)record->timestamp;
        struct tm *tm_info = localtime(&t);
        if (tm_info) {
            strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);
        }
        json_object_object_add(record_obj, "time_str", json_object_new_string(time_str));
        
        
        char duration_str[64] = {0};
        unsigned long long hours = record->duration / 3600;
        unsigned long long minutes = (record->duration % 3600) / 60;
        unsigned long long seconds = record->duration % 60;
        if (hours > 0) {
            snprintf(duration_str, sizeof(duration_str), "%lluh%llum%llus", hours, minutes, seconds);
        } else if (minutes > 0) {
            snprintf(duration_str, sizeof(duration_str), "%llum%llus", minutes, seconds);
        } else {
            snprintf(duration_str, sizeof(duration_str), "%llus", seconds);
        }
        json_object_object_add(record_obj, "duration_str", json_object_new_string(duration_str));
        
        json_object_array_add(records_array, record_obj);
        record_count++;
    }
    
    json_object_object_add(data_obj, "mac", json_object_new_string(mac));
    json_object_object_add(data_obj, "records", records_array);
    json_object_object_add(data_obj, "count", json_object_new_int(record_count));
    
    LOG_DEBUG("jmx_api_get_online_offline_records: success, returning %d records for mac=%s\n", record_count, mac);
    return jmx_gen_api_response_data(API_CODE_SUCCESS, data_obj);
}


struct json_object *jmx_api_get_record_base(struct json_object *req_obj) {
    struct json_object *data_obj = json_object_new_object();
    jmx_legacy_settings_t settings;
    if (jmx_legacy_settings_get(&settings) != 0) {
        json_object_put(data_obj);
        return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    json_object_object_add(data_obj, "enable", json_object_new_int(settings.record_enabled));
    json_object_object_add(data_obj, "record_time", json_object_new_int(settings.record_time));
    json_object_object_add(data_obj, "app_valid_time", json_object_new_int(settings.app_valid_time));
    json_object_object_add(data_obj, "history_data_size", json_object_new_string(settings.history_data_size));
    json_object_object_add(data_obj, "history_data_path", json_object_new_string(settings.history_data_path));

    struct json_object *status_obj = json_object_new_object();
    char data_dir[512] = {0};
    if (settings.history_data_path[0]) {
        snprintf(data_dir, sizeof(data_dir), "%s/client_data", settings.history_data_path);
    } else {
        strncpy(data_dir, CLIENT_DATA_BASE_DIR_DEFAULT, sizeof(data_dir) - 1);
    }
    
    char cmd[1024] = {0};
    char result[256] = {0};
    snprintf(cmd, sizeof(cmd), "du -sk %s 2>/dev/null | awk '{print $1}'", data_dir);
    if (exec_with_result_line(cmd, result, sizeof(result)) == 0 && strlen(result) > 0) {
        unsigned long long data_size_kb = strtoull(result, NULL, 10);
        json_object_object_add(status_obj, "data_size", json_object_new_int64(data_size_kb));
        json_object_object_add(status_obj, "data_size_unit", json_object_new_string("KB"));
    } else {
        json_object_object_add(status_obj, "data_size", json_object_new_int64(0));
        json_object_object_add(status_obj, "data_size_unit", json_object_new_string("KB"));
    }
    json_object_object_add(data_obj, "status", status_obj);

    return jmx_gen_api_response_data(API_CODE_SUCCESS, data_obj);
}

struct json_object *jmx_api_set_record_base(struct json_object *req_obj) {
    jmx_legacy_settings_t old_settings;
    if (jmx_legacy_settings_get(&old_settings) != 0) {
        return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
    }

    int enable = 0, record_time = 0, app_valid_time = 0;
    const char *history_data_size = NULL;
    const char *history_data_path = NULL;
    struct json_object *v;
    if (req_obj && json_object_object_get_ex(req_obj, "enable", &v) && v)
        enable = json_object_get_int(v);
    if (req_obj && json_object_object_get_ex(req_obj, "record_time", &v) && v)
        record_time = json_object_get_int(v);
    if (req_obj && json_object_object_get_ex(req_obj, "app_valid_time", &v) && v)
        app_valid_time = json_object_get_int(v);
    if (req_obj && json_object_object_get_ex(req_obj, "history_data_size", &v) && v)
        history_data_size = json_object_get_string(v);
    if (req_obj && json_object_object_get_ex(req_obj, "history_data_path", &v) && v)
        history_data_path = json_object_get_string(v);

    if (enable < 0) enable = 0;
    if (record_time < 0) record_time = 0;
    if (app_valid_time < 0) app_valid_time = 0;

    if (history_data_size && strlen(history_data_size) > 0) {
        char *endptr = NULL;
        long size_val = strtol(history_data_size, &endptr, 10);
        if (*endptr != '\0' || size_val < 1 || size_val > 1024) {
            return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
        }
    }

    if (!history_data_path || strlen(history_data_path) == 0) {
        return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
    }

    if (strcmp(history_data_path, "/") == 0) {
        return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
    }

    if (strlen(history_data_path) > 64) {
        return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    if (!history_data_size || !history_data_size[0])
        history_data_size = old_settings.history_data_size;
    if (jmx_legacy_settings_set_record(enable ? 1 : 0, record_time,
                                       app_valid_time, history_data_size,
                                       history_data_path) != 0)
        return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
    
    if (history_data_path && strlen(history_data_path) > 0) {
        char old_data_dir[512] = {0};
        char new_data_dir[512] = {0};
        
        if (old_settings.history_data_path[0] &&
            strcmp(old_settings.history_data_path, history_data_path) != 0) {
            snprintf(old_data_dir, sizeof(old_data_dir), "%s/client_data", old_settings.history_data_path);
            snprintf(new_data_dir, sizeof(new_data_dir), "%s/client_data", history_data_path);
            
            char cmd[2048] = {0};
            snprintf(cmd, sizeof(cmd), "mkdir -p %s && mv %s/* %s/ 2>/dev/null; true", 
                     new_data_dir, old_data_dir, new_data_dir);
            
            system(cmd);
            LOG_WARN("22cmd: %s\n", cmd);
            LOG_WARN("move old data to new path: %s -> %s\n",
                     old_settings.history_data_path, history_data_path);
        }
        
        reset_client_data_base_dir_cache();
    }
    
    update_jmx_proc_u32_value("record_enable", enable);
    

    load_app_valid_time_config();

    return jmx_gen_api_response_data(API_CODE_SUCCESS, NULL);
}

struct json_object *jmx_api_record_action(struct json_object *req_obj) {
    if (!req_obj) {
        return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    struct json_object *action_obj = json_object_object_get(req_obj, "action");
    if (!action_obj) {
        return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    const char *action = json_object_get_string(action_obj);
    if (!action) {
        return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    if (strcmp(action, "clean_all_data") == 0) {
        jmx_legacy_settings_t settings;
        if (jmx_legacy_settings_get(&settings) != 0) {
            return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
        }
        
        char data_dir[512] = {0};
        if (settings.history_data_path[0]) {
            snprintf(data_dir, sizeof(data_dir), "%s/client_data", settings.history_data_path);
        } else {
            strncpy(data_dir, CLIENT_DATA_BASE_DIR_DEFAULT, sizeof(data_dir) - 1);
        }
        
        char cmd[1024] = {0};
        snprintf(cmd, sizeof(cmd), "rm -rf %s/* 2>/dev/null; true", data_dir);
        system(cmd);
        
        reset_client_data_base_dir_cache();
        
        return jmx_gen_api_response_data(API_CODE_SUCCESS, NULL);
    }
    
    return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
}

struct json_object *jmx_api_get_device_list(struct json_object *req_obj) {
    LOG_DEBUG("jmx_api_get_device_list: called\n");
    
    struct json_object *data_obj = json_object_new_object();
    struct json_object *device_array = json_object_new_array();
    
    FILE *fp = jmx_fopen_af("dev", "r");
    if (!fp) {
        LOG_ERROR("Failed to open /proc/net/dev\n");
        json_object_put(data_obj);
        return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    char line[256];
    int line_num = 0;
    

    while (fgets(line, sizeof(line), fp)) {
        line_num++;
        

        if (line_num <= 2) {
            continue;
        }
        

        char *colon = strchr(line, ':');
        if (!colon) {
            continue;
        }
        
 
        int ifname_len = colon - line;
        if (ifname_len <= 0 || ifname_len >= 64) {
            continue;
        }
        
        char ifname[64] = {0};
        strncpy(ifname, line, ifname_len);
        

        char *ifname_start = ifname;
        while (*ifname_start == ' ' || *ifname_start == '\t') {
            ifname_start++;
        }
    
        if (strcmp(ifname_start, "lo") == 0) {
            continue;
        }

        if (strlen(ifname_start) == 0) {
            continue;
        }

        json_object_array_add(device_array, json_object_new_string(ifname_start));
        LOG_DEBUG("Added interface: %s\n", ifname_start);
    }
    
    fclose(fp);
    
    json_object_object_add(data_obj, "device_list", device_array);
    LOG_DEBUG("jmx_api_get_device_list: returning %d devices\n", json_object_array_length(device_array));
    return jmx_gen_api_response_data(API_CODE_SUCCESS, data_obj);
}


struct json_object *jmx_api_get_dashboard_param(struct json_object *req_obj) {
    LOG_DEBUG("jmx_api_get_dashboard_param: called\n");
    jmx_legacy_settings_t settings;
    if (jmx_legacy_settings_get(&settings) != 0) {
        LOG_ERROR("Failed to read dashboard settings from config.db\n");
        return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    struct json_object *data_obj = json_object_new_object();
    json_object_object_add(data_obj, "monitor_device",
                           json_object_new_string(settings.monitor_device));
    
    LOG_DEBUG("jmx_api_get_dashboard_param: monitor_device=%s\n",
              settings.monitor_device);
    return jmx_gen_api_response_data(API_CODE_SUCCESS, data_obj);
}

struct json_object *jmx_api_set_dashboard_param(struct json_object *req_obj) {
    
    if (!req_obj) {
        return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    struct json_object *monitor_device_obj = json_object_object_get(req_obj, "monitor_device");
    if (!monitor_device_obj) {
        LOG_ERROR("monitor_device parameter missing\n");
        return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    const char *monitor_device = json_object_get_string(monitor_device_obj);
    
    if (!monitor_device || strlen(monitor_device) >= 64 ||
        jmx_legacy_settings_set_dashboard(monitor_device) != 0) {
        LOG_ERROR("Failed to commit dashboard settings to config.db\n");
        return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    g_interface_name[0] = '\0';
    
    LOG_DEBUG("jmx_api_set_dashboard_param: set monitor_device=%s\n", monitor_device ? monitor_device : "(empty)");
    return jmx_gen_api_response_data(API_CODE_SUCCESS, NULL);
}


typedef struct json_object * (*jmx_api_handler)(struct json_object *data_obj);

typedef struct jmx_api_node{
    char *api_name;
    jmx_api_handler handler;
}jmx_api_node_t;

struct json_object *jmx_api_get_dashboard_common(struct json_object *req_obj);
struct json_object *jmx_api_get_hourly_top_apps(struct json_object *req_obj);
struct json_object *jmx_api_get_daily_top_apps(struct json_object *req_obj);
struct json_object *jmx_api_delete_record_files(struct json_object *req_obj);
struct json_object *jmx_api_get_global_app_type_stats(struct json_object *req_obj);
struct json_object *jmx_api_get_global_traffic_stats(struct json_object *req_obj);
struct json_object *jmx_api_get_daily_top_users(struct json_object *req_obj);
struct json_object *jmx_api_get_active_users(struct json_object *req_obj);
struct json_object *jmx_api_get_filter_rules(struct json_object *req_obj);
struct json_object *jmx_api_add_filter_rule(struct json_object *req_obj);
struct json_object *jmx_api_update_filter_rule(struct json_object *req_obj);
struct json_object *jmx_api_delete_filter_rule(struct json_object *req_obj);
struct json_object *jmx_api_get_user_basic_info(struct json_object *req_obj);
struct json_object *jmx_api_get_online_offline_records(struct json_object *req_obj);
struct json_object *jmx_api_get_record_base(struct json_object *req_obj);
struct json_object *jmx_api_get_user_records(struct json_object *req_obj);
struct json_object *jmx_api_get_history_session(struct json_object *req_obj);
struct json_object *jmx_api_get_feature_info(struct json_object *req_obj);
struct json_object *jmx_api_get_feature_class_list(struct json_object *req_obj);
struct json_object *jmx_api_set_record_base(struct json_object *req_obj);
struct json_object *jmx_api_record_action(struct json_object *req_obj);
struct json_object *jmx_api_set_nickname(struct json_object *req_obj);
struct json_object *jmx_api_dev_visit_list(struct json_object *req_obj);
struct json_object *jmx_api_dev_visit_time(struct json_object *req_obj);
struct json_object *jmx_api_app_class_visit_time(struct json_object *req_obj);
struct json_object *jmx_api_dev_list(struct json_object *req_obj);
struct json_object *jmx_api_class_list(struct json_object *req_obj);
struct json_object *jmx_api_get_all_users(struct json_object *req_obj);
struct json_object *jmx_api_get_oaf_status(struct json_object *req_obj);
struct json_object *jmx_api_visit_list(struct json_object *req_obj);
struct json_object *jmx_api_get_device_list(struct json_object *req_obj);
struct json_object *jmx_api_get_dashboard_param(struct json_object *req_obj);
struct json_object *jmx_api_set_dashboard_param(struct json_object *req_obj);
struct json_object *jmx_api_route_wan_register(struct json_object *req_obj);
struct json_object *jmx_api_route_wan_unregister(struct json_object *req_obj);
struct json_object *jmx_api_route_wan_health(struct json_object *req_obj);
struct json_object *jmx_api_route_rule_add(struct json_object *req_obj);
struct json_object *jmx_api_route_rule_del(struct json_object *req_obj);
struct json_object *jmx_api_route_rule_flush(struct json_object *req_obj);
struct json_object *jmx_api_route_rule_clear_hits(struct json_object *req_obj);
struct json_object *jmx_api_route_status(struct json_object *req_obj);
struct json_object *jmx_api_route_reload(struct json_object *req_obj);
struct json_object *jmx_api_route_config_get(struct json_object *req_obj);
struct json_object *jmx_api_route_config_set(struct json_object *req_obj);




/* ── Phase 6: Domain stats API ── */
struct json_object *jmx_api_get_domain_stats(struct json_object *req_obj) {
    struct json_object *data = json_object_new_object();
    struct json_object *groups = json_object_new_array();
    json_object_object_add(data, "total_domains", json_object_new_int(jmx_domain_count()));
    json_object_object_add(data, "total_groups", json_object_new_int(jmx_domain_group_count()));
    /* TODO: iterate groups and add to array */
    json_object_object_add(data, "groups", groups);
    return jmx_gen_api_response_data(API_CODE_SUCCESS, data);
}

/* ── Phase 6: Hosttype stats API ── */
struct json_object *jmx_api_get_hosttype_stats(struct json_object *req_obj) {
    struct json_object *data = json_object_new_object();
    json_object_object_add(data, "ua_fingerprints", json_object_new_int(jmx_ht_ua_count()));
    json_object_object_add(data, "vendor_entries", json_object_new_int(jmx_ht_oui_count()));
    return jmx_gen_api_response_data(API_CODE_SUCCESS, data);
}

/* ── Phase 6: DPI stats API ── */
struct json_object *jmx_api_get_dpi_stats(struct json_object *req_obj) {
    struct json_object *data = json_object_new_object();
    json_object_object_add(data, "regex_rules", json_object_new_int(3534));
    json_object_object_add(data, "nr_rules", json_object_new_int(98));
    json_object_object_add(data, "domain_count", json_object_new_int(jmx_domain_count()));
    json_object_object_add(data, "ua_count", json_object_new_int(jmx_ht_ua_count()));
    json_object_object_add(data, "audit_total", json_object_new_int64(jmx_audit_total_events()));
    json_object_object_add(data, "nfqueue_packets", json_object_new_int64(jmx_regex_stat_packets()));
    json_object_object_add(data, "nfqueue_matched", json_object_new_int64(jmx_regex_stat_matched()));
    return jmx_gen_api_response_data(API_CODE_SUCCESS, data);
}

/* ── Phase 6: Rule reload API ── */
struct json_object *jmx_api_reload_rules(struct json_object *req_obj) {
    struct json_object *data = json_object_new_object();
    struct json_object *apply_req = json_object_new_object();
    struct json_object *route_resp = NULL, *netctl_resp = NULL, *sig_resp = NULL;

    int apply_nft = 1, apply_tc = 1;
    if (req_obj) {
        struct json_object *v = NULL;
        if (json_object_object_get_ex(req_obj, "apply_nft", &v)) apply_nft = json_object_get_boolean(v);
        if (json_object_object_get_ex(req_obj, "apply_tc", &v)) apply_tc = json_object_get_boolean(v);
        struct json_object *payload = NULL;
        if (json_object_object_get_ex(req_obj, "data", &payload) && payload) {
            if (json_object_object_get_ex(payload, "apply_nft", &v)) apply_nft = json_object_get_boolean(v);
            if (json_object_object_get_ex(payload, "apply_tc", &v)) apply_tc = json_object_get_boolean(v);
        }
    }

    json_object_object_add(apply_req, "dry_run", json_object_new_boolean(0));
    json_object_object_add(apply_req, "apply_nft", json_object_new_boolean(apply_nft));
    json_object_object_add(apply_req, "apply_tc", json_object_new_boolean(apply_tc));

    const char *sig_path = NULL;
    struct json_object *path_obj = NULL;
    if (req_obj && json_object_object_get_ex(req_obj, "signature_db", &path_obj)) sig_path = json_object_get_string(path_obj);
    if (req_obj) {
        struct json_object *payload = NULL;
        if (json_object_object_get_ex(req_obj, "data", &payload) && payload && json_object_object_get_ex(payload, "signature_db", &path_obj))
            sig_path = json_object_get_string(path_obj);
    }
    int sig_reload_rc = jmx_runtime_reload_signature_db(sig_path);

    route_resp = jmx_api_route_reload(req_obj);
    netctl_resp = jmx_network_control_apply(apply_req);
    sig_resp = jmx_signature_db_status(req_obj);

    json_object_object_add(data, "status", json_object_new_string(sig_reload_rc == 0 ? "reloaded" : "reload_partial_signature_failed"));
    json_object_object_add(data, "signature_reload_rc", json_object_new_int(sig_reload_rc));
    json_object_object_add(data, "route", route_resp ? route_resp : json_object_new_null());
    json_object_object_add(data, "network_control", netctl_resp ? netctl_resp : json_object_new_null());
    json_object_object_add(data, "signature_db", sig_resp ? sig_resp : json_object_new_null());
    json_object_object_add(data, "runtime_note", json_object_new_string("signature engine hot-swap executed in-process; network_control nft/tc apply runs by default unless explicitly disabled"));

    json_object_put(apply_req);
    return jmx_gen_api_response_data(API_CODE_SUCCESS, data);
}


/* ── get_user_records: per-user online/offline records ── */
struct json_object *jmx_api_get_user_records(struct json_object *req_obj) {
    struct json_object *data = json_object_new_object();
    struct json_object *list = json_object_new_array();

    const char *mac = NULL;
    int page = 1, page_size = 15;
    int row = 0;

    struct json_object *data_obj = NULL;
    if (json_object_object_get_ex(req_obj, "data", &data_obj)) {
        struct json_object *tmp;
        if (json_object_object_get_ex(data_obj, "mac", &tmp))
            mac = json_object_get_string(tmp);
        if (json_object_object_get_ex(data_obj, "page", &tmp))
            page = json_object_get_int(tmp);
        if (json_object_object_get_ex(data_obj, "page_size", &tmp))
            page_size = json_object_get_int(tmp);
    }
    if (page < 1)
        page = 1;
    if (page_size < 1)
        page_size = 15;

    /* Read from /proc/net/af_client for online clients */
    FILE *fp = jmx_fopen_af("af_client", "r");
    if (fp) {
        char line[512];
        while (fgets(line, sizeof(line), fp)) {
            if (line[0] == 'I' || line[0] == 'M' || line[0] == '-' || line[0] == '\n')
                continue;
            char mac_buf[32] = {0}, ip_buf[48] = {0};
            char ipv6_buf[64] = {0};
            unsigned long long up = 0, down = 0;
            int id = 0;
            int parsed = sscanf(line, "%d %31s %47s %63s %llu %llu",
                                &id, mac_buf, ip_buf, ipv6_buf, &up, &down);
            if (parsed < 3)
                parsed = sscanf(line, "%31s %47s %llu %llu", mac_buf, ip_buf, &up, &down);
            if (parsed >= 2) {
                if (mac && mac[0] && strcasecmp(mac_buf, mac) != 0)
                    continue;
                row++;
                if (row < (page - 1) * page_size + 1)
                    continue;
                if (row > page * page_size)
                    continue;

                struct json_object *rec = json_object_new_object();
                json_object_object_add(rec, "mac", json_object_new_string(mac_buf));
                json_object_object_add(rec, "ip", json_object_new_string(ip_buf));
                json_object_object_add(rec, "action", json_object_new_int(0)); /* online */
                json_object_object_add(rec, "up_bytes", json_object_new_int64(up));
                json_object_object_add(rec, "down_bytes", json_object_new_int64(down));
                json_object_object_add(rec, "online_duration", json_object_new_int(0));
                json_object_object_add(rec, "active_duration", json_object_new_int(0));
                json_object_object_add(rec, "recent_apps", json_object_new_array());
                json_object_object_add(rec, "time_str", json_object_new_string(""));
                json_object_array_add(list, rec);
            }
        }
        fclose(fp);
    }

    int total = row;
    json_object_object_add(data, "total_num", json_object_new_int(total));
    json_object_object_add(data, "total_page", json_object_new_int(total > 0 ? (total + page_size - 1) / page_size : 0));
    json_object_object_add(data, "page", json_object_new_int(page));
    json_object_object_add(data, "list", list);

    return jmx_gen_api_response_data(API_CODE_SUCCESS, data);
}

/* ── get_history_session: session count statistics ── */
struct json_object *jmx_api_get_history_session(struct json_object *req_obj) {
    struct json_object *data = json_object_new_object();
    const char *range = "hour";

    struct json_object *data_obj = NULL;
    if (json_object_object_get_ex(req_obj, "data", &data_obj)) {
        struct json_object *tmp;
        if (json_object_object_get_ex(data_obj, "range", &tmp))
            range = json_object_get_string(tmp);
    }

    int minutes = 60;
    if (strcmp(range, "day") == 0) minutes = 1440;
    else if (strcmp(range, "5min") == 0) minutes = 5;

    /* Count current connections from /proc/net/af_conn */
    int current = 0;
    FILE *fp = jmx_fopen_af("af_conn", "r");
    if (fp) {
        char line[512];
        while (fgets(line, sizeof(line), fp))
            current++;
        fclose(fp);
        if (current > 0) current--; /* subtract header */
    }

    struct json_object *list = json_object_new_array();

    json_object_object_add(data, "range", json_object_new_string(range));
    json_object_object_add(data, "minutes", json_object_new_int(minutes));
    json_object_object_add(data, "current", json_object_new_int(current));
    json_object_object_add(data, "current_supported", json_object_new_boolean(1));
    json_object_object_add(data, "history_supported", json_object_new_boolean(0));
    json_object_object_add(data, "complete", json_object_new_boolean(0));
    json_object_object_add(data, "source", json_object_new_string("proc_af_conn_current"));
    json_object_object_add(data, "reason",
                           json_object_new_string("history_aggregation_unavailable"));
    json_object_object_add(data, "interval_seconds", json_object_new_int(0));
    json_object_object_add(data, "avg", json_object_new_null());
    json_object_object_add(data, "peak", json_object_new_null());
    json_object_object_add(data, "list", list);

    return jmx_gen_api_response_data(API_CODE_SUCCESS, data);
}

/* ── get_feature_info: feature library info ── */
struct json_object *jmx_api_get_feature_info(struct json_object *req_obj) {
    (void)req_obj;
    struct json_object *data = json_object_new_object();

    sqlite3 *db = NULL;
    sqlite3_stmt *st = NULL;
    const char *schema_version = "";
    const char *protocol_source = "";
    int app_count = 0;

    if (jmx_signature_db_open(&db) == 0) {
        if (sqlite3_prepare_v2(db,
                "SELECT COUNT(*) FROM app WHERE enabled=1", -1, &st, NULL) == SQLITE_OK &&
            sqlite3_step(st) == SQLITE_ROW)
            app_count = sqlite3_column_int(st, 0);
        sqlite3_finalize(st);
        st = NULL;
        if (sqlite3_prepare_v2(db,
                "SELECT COALESCE(MAX(CASE WHEN key='schema_version' THEN value END),''),"
                "COALESCE(MAX(CASE WHEN key='protocol_augment_source' THEN value END),'') "
                "FROM meta WHERE key IN ('schema_version','protocol_augment_source')",
                -1, &st, NULL) == SQLITE_OK && sqlite3_step(st) == SQLITE_ROW) {
            const char *v = (const char *)sqlite3_column_text(st, 0);
            const char *s = (const char *)sqlite3_column_text(st, 1);
            schema_version = v ? v : "";
            protocol_source = s ? s : "";
            json_object_object_add(data, "version", json_object_new_string(schema_version));
            json_object_object_add(data, "format", json_object_new_string("sqlite"));
            json_object_object_add(data, "source", json_object_new_string(protocol_source));
        }
        sqlite3_finalize(st);
        jmx_signature_db_close(db);
    }
    if (!json_object_object_get(data, "version")) {
        json_object_object_add(data, "version", json_object_new_string(""));
        json_object_object_add(data, "format", json_object_new_string("sqlite"));
        json_object_object_add(data, "source", json_object_new_string(""));
    }
    json_object_object_add(data, "app_count", json_object_new_int(app_count));
    json_object_object_add(data, "authority",
                           json_object_new_string("dreamingwrt_signatures.db"));

    return jmx_gen_api_response_data(API_CODE_SUCCESS, data);
}

/* ── get_feature_class_list: feature class list ── */
/* Already handled by class_list API - just alias it */
struct json_object *jmx_api_get_feature_class_list(struct json_object *req_obj) {
    return jmx_api_class_list(req_obj);
}


/* DreamingWrt network-config aliases for jmx common API */
static struct json_object *jmx_api_net_global_get(struct json_object *req_obj)
{
    (void)req_obj;
    return jmx_netconfig_global_get();
}

static struct json_object *jmx_api_net_global_set(struct json_object *req_obj)
{
    (void)req_obj;
    struct json_object *data = json_object_new_object();
    json_object_object_add(data, "ok", json_object_new_boolean(0));
    json_object_object_add(data, "error", json_object_new_string("capability_disabled"));
    json_object_object_add(data, "capability", json_object_new_string("network_global_apply"));
    json_object_object_add(data, "persisted", json_object_new_boolean(0));
    json_object_object_add(data, "applied", json_object_new_boolean(0));
    json_object_object_add(data, "apply_state", json_object_new_string("unsupported"));
    json_object_object_add(data, "reason",
                           json_object_new_string("transactional_global_network_executor_pending"));
    return jmx_gen_api_response_data(API_CODE_ERROR, data);
}

static struct json_object *jmx_api_physical_port_list(struct json_object *req_obj)
{
    (void)req_obj;
    return jmx_netconfig_physical_port_list();
}

static struct json_object *jmx_api_physical_port_refresh(struct json_object *req_obj)
{
    (void)req_obj;
    struct json_object *data = json_object_new_object();
    int rc = jmx_netconfig_physical_port_refresh();
    json_object_object_add(data, "ok", json_object_new_boolean(rc == 0));
    return jmx_gen_api_response_data(rc == 0 ? API_CODE_SUCCESS : API_CODE_ERROR, data);
}

static struct json_object *jmx_api_radius_list(struct json_object *req_obj)
{
    (void)req_obj;
    return jmx_netconfig_radius_list();
}

static struct json_object *jmx_api_radius_set(struct json_object *req_obj)
{
    struct json_object *data = json_object_new_object();
    int rc = jmx_netconfig_radius_set(req_obj);
    json_object_object_add(data, "ok", json_object_new_boolean(rc == 0));
    return jmx_gen_api_response_data(rc == 0 ? API_CODE_SUCCESS : API_CODE_ERROR, data);
}

static struct json_object *jmx_api_radius_delete(struct json_object *req_obj)
{
    const char *id = "";
    struct json_object *v = NULL;
    struct json_object *data = json_object_new_object();
    if (req_obj && json_object_object_get_ex(req_obj, "id", &v) && v) id = json_object_get_string(v);
    int rc = jmx_netconfig_radius_delete(id);
    json_object_object_add(data, "ok", json_object_new_boolean(rc == 0));
    return jmx_gen_api_response_data(rc == 0 ? API_CODE_SUCCESS : API_CODE_ERROR, data);
}

static struct json_object *jmx_api_hybrid_line_list(struct json_object *req_obj)
{
    const char *parent = "";
    struct json_object *v = NULL;
    if (req_obj && json_object_object_get_ex(req_obj, "parent", &v) && v) parent = json_object_get_string(v);
    return jmx_netconfig_hybrid_line_list(parent);
}

static struct json_object *jmx_api_hybrid_line_set(struct json_object *req_obj)
{
    struct json_object *data = json_object_new_object();
    const char *id = "";
    struct json_object *v = NULL;
    int rc = jmx_netconfig_hybrid_line_set(req_obj);
    if (req_obj && json_object_object_get_ex(req_obj, "id", &v) && v) id = json_object_get_string(v);
    int arc = (rc == 0 && id && id[0]) ? jmx_netconfig_apply_hybrid_line(id) : 0;
    json_object_object_add(data, "ok", json_object_new_boolean(rc == 0 && arc == 0));
    json_object_object_add(data, "saved", json_object_new_boolean(rc == 0));
    json_object_object_add(data, "applied", json_object_new_boolean(arc == 0));
    return jmx_gen_api_response_data((rc == 0 && arc == 0) ? API_CODE_SUCCESS : API_CODE_ERROR, data);
}

static struct json_object *jmx_api_hybrid_line_delete(struct json_object *req_obj)
{
    const char *id = "";
    struct json_object *v = NULL;
    struct json_object *data = json_object_new_object();
    if (req_obj && json_object_object_get_ex(req_obj, "id", &v) && v) id = json_object_get_string(v);
    int rc = jmx_netconfig_hybrid_line_delete(id);
    json_object_object_add(data, "ok", json_object_new_boolean(rc == 0));
    return jmx_gen_api_response_data(rc == 0 ? API_CODE_SUCCESS : API_CODE_ERROR, data);
}

static struct json_object *jmx_api_hybrid_line_enable(struct json_object *req_obj)
{
    const char *id = "";
    struct json_object *v = NULL;
    struct json_object *data = json_object_new_object();
    int enabled = 1;
    if (req_obj && json_object_object_get_ex(req_obj, "id", &v) && v) id = json_object_get_string(v);
    if (req_obj && json_object_object_get_ex(req_obj, "enabled", &v) && v) enabled = json_object_get_boolean(v);
    int rc = jmx_netconfig_hybrid_line_enable(id, enabled);
    int arc = (rc == 0 && enabled) ? jmx_netconfig_apply_hybrid_line(id) : 0;
    json_object_object_add(data, "ok", json_object_new_boolean(rc == 0 && arc == 0));
    json_object_object_add(data, "saved", json_object_new_boolean(rc == 0));
    json_object_object_add(data, "applied", json_object_new_boolean(arc == 0));
    return jmx_gen_api_response_data((rc == 0 && arc == 0) ? API_CODE_SUCCESS : API_CODE_ERROR, data);
}

static struct json_object *jmx_api_dreamingwrt_topology_flow(struct json_object *req_obj)
{ (void)req_obj; struct json_object *data = jmx_dreamingwrt_topology_flow_get(); return jmx_gen_api_response_data(API_CODE_SUCCESS, data); }






/* Firewall service aliases for jmx common API */
static struct json_object *jmx_api_firewall_service_get(struct json_object *req_obj)
{ (void)req_obj; return jmx_firewall_service_get(); }
static struct json_object *jmx_api_firewall_service_set(struct json_object *req_obj)
{ struct json_object *data=json_object_new_object(); int rc=jmx_firewall_service_set(req_obj); json_object_object_add(data,"ok",json_object_new_boolean(rc==0)); json_object_object_add(data,"saved",json_object_new_boolean(rc==0)); return jmx_gen_api_response_data(rc==0?API_CODE_SUCCESS:API_CODE_ERROR,data); }
static struct json_object *jmx_api_firewall_service_apply(struct json_object *req_obj)
{ return jmx_firewall_service_apply(req_obj); }

/* Flow control aliases for jmx common API */
static struct json_object *jmx_api_flow_control_get(struct json_object *req_obj)
{ (void)req_obj; return jmx_flow_control_get(); }
static struct json_object *jmx_api_flow_control_set(struct json_object *req_obj)
{ struct json_object *data=json_object_new_object(); int rc=jmx_flow_control_set(req_obj); json_object_object_add(data,"ok",json_object_new_boolean(rc==0)); json_object_object_add(data,"saved",json_object_new_boolean(rc==0)); return jmx_gen_api_response_data(rc==0?API_CODE_SUCCESS:API_CODE_ERROR,data); }
static struct json_object *jmx_api_flow_control_apply(struct json_object *req_obj)
{ return jmx_flow_control_apply(req_obj); }
static struct json_object *jmx_api_flow_control_rule_test(struct json_object *req_obj)
{ return jmx_flow_control_rule_test(req_obj); }

/* VPN config aliases for jmx common API */
static struct json_object *jmx_api_vpn_config_get(struct json_object *req_obj)
{ (void)req_obj; return jmx_vpn_config_get(); }
static struct json_object *jmx_api_vpn_config_set(struct json_object *req_obj)
{ struct json_object *data=json_object_new_object(); int rc=jmx_vpn_config_set(req_obj); json_object_object_add(data,"ok",json_object_new_boolean(rc==0)); json_object_object_add(data,"saved",json_object_new_boolean(rc==0)); return jmx_gen_api_response_data(rc==0?API_CODE_SUCCESS:API_CODE_ERROR,data); }

static struct json_object *jmx_api_vpn_server_set(struct json_object *req_obj)
{ struct json_object *data=json_object_new_object(); int rc=jmx_vpn_server_set(req_obj); json_object_object_add(data,"ok",json_object_new_boolean(rc==0)); json_object_object_add(data,"saved",json_object_new_boolean(rc==0)); return jmx_gen_api_response_data(rc==0?API_CODE_SUCCESS:API_CODE_ERROR,data); }
static struct json_object *jmx_api_vpn_client_set(struct json_object *req_obj)
{ struct json_object *data=json_object_new_object(); int rc=jmx_vpn_client_set(req_obj); json_object_object_add(data,"ok",json_object_new_boolean(rc==0)); json_object_object_add(data,"saved",json_object_new_boolean(rc==0)); return jmx_gen_api_response_data(rc==0?API_CODE_SUCCESS:API_CODE_ERROR,data); }
static struct json_object *jmx_api_vpn_site_set(struct json_object *req_obj)
{ struct json_object *data=json_object_new_object(); int rc=jmx_vpn_site_set(req_obj); json_object_object_add(data,"ok",json_object_new_boolean(rc==0)); json_object_object_add(data,"saved",json_object_new_boolean(rc==0)); return jmx_gen_api_response_data(rc==0?API_CODE_SUCCESS:API_CODE_ERROR,data); }
static struct json_object *jmx_api_vpn_account_set(struct json_object *req_obj)
{ struct json_object *data=json_object_new_object(); int rc=jmx_vpn_account_set(req_obj); json_object_object_add(data,"ok",json_object_new_boolean(rc==0)); json_object_object_add(data,"saved",json_object_new_boolean(rc==0)); return jmx_gen_api_response_data(rc==0?API_CODE_SUCCESS:API_CODE_ERROR,data); }
static struct json_object *jmx_api_vpn_certificate_set(struct json_object *req_obj)
{ struct json_object *data=json_object_new_object(); int rc=jmx_vpn_certificate_set(req_obj); json_object_object_add(data,"ok",json_object_new_boolean(rc==0)); json_object_object_add(data,"saved",json_object_new_boolean(rc==0)); return jmx_gen_api_response_data(rc==0?API_CODE_SUCCESS:API_CODE_ERROR,data); }

static struct json_object *jmx_api_vpn_config_apply(struct json_object *req_obj)
{ return jmx_vpn_config_apply(req_obj); }

/* Bulk IP / IPAM aliases for jmx common API */
static struct json_object *jmx_api_bulk_ip_get(struct json_object *req_obj)
{ (void)req_obj; return jmx_bulk_ip_get(); }
static struct json_object *jmx_api_bulk_ip_set(struct json_object *req_obj)
{ struct json_object *data=json_object_new_object(); int rc=jmx_bulk_ip_set(req_obj); json_object_object_add(data,"ok",json_object_new_boolean(rc==0)); json_object_object_add(data,"saved",json_object_new_boolean(rc==0)); return jmx_gen_api_response_data(rc==0?API_CODE_SUCCESS:API_CODE_ERROR,data); }
static struct json_object *jmx_api_bulk_ip_import(struct json_object *req_obj)
{ return jmx_bulk_ip_import(req_obj); }
static struct json_object *jmx_api_bulk_ip_export(struct json_object *req_obj)
{ return jmx_bulk_ip_export(req_obj); }

/* Multicast service aliases for jmx common API */
static struct json_object *jmx_api_multicast_service_get(struct json_object *req_obj)
{ (void)req_obj; return jmx_multicast_service_get(); }

static struct json_object *jmx_api_multicast_service_set(struct json_object *req_obj)
{
    struct json_object *data = json_object_new_object();
    int rc = jmx_multicast_service_set(req_obj);
    json_object_object_add(data, "ok", json_object_new_boolean(rc == 0));
    json_object_object_add(data, "saved", json_object_new_boolean(rc == 0));
    return jmx_gen_api_response_data(rc == 0 ? API_CODE_SUCCESS : API_CODE_ERROR, data);
}

static struct json_object *jmx_api_multicast_service_apply(struct json_object *req_obj)
{
    struct json_object *data = json_object_new_object();
    struct json_object *v = NULL;
    int dry_run = 0;
    if (req_obj && json_object_object_get_ex(req_obj, "dry_run", &v) && v) dry_run = json_object_get_boolean(v);
    int rc = jmx_multicast_service_apply(dry_run);
    json_object_object_add(data, "ok", json_object_new_boolean(rc == 0));
    json_object_object_add(data, "applied", json_object_new_boolean(rc == 0 && !dry_run));
    json_object_object_add(data, "dry_run", json_object_new_boolean(dry_run));
    return jmx_gen_api_response_data(rc == 0 ? API_CODE_SUCCESS : API_CODE_ERROR, data);
}

/* DHCP service aliases for jmx common API */
static struct json_object *jmx_api_dhcp_service_get(struct json_object *req_obj)
{ (void)req_obj; return jmx_dhcp_service_get(); }
static struct json_object *jmx_api_dhcp_service_set(struct json_object *req_obj)
{ struct json_object *data=json_object_new_object(); const char *lan_id=""; struct json_object *v=NULL; if(req_obj&&json_object_object_get_ex(req_obj,"lan_id",&v)&&v)lan_id=json_object_get_string(v); int rc=jmx_dhcp_service_set(req_obj); int arc=(rc==0)?jmx_dhcp_service_apply(lan_id):-1; json_object_object_add(data,"ok",json_object_new_boolean(rc==0&&arc==0)); json_object_object_add(data,"saved",json_object_new_boolean(rc==0)); json_object_object_add(data,"applied",json_object_new_boolean(arc==0)); return jmx_gen_api_response_data((rc==0&&arc==0)?API_CODE_SUCCESS:API_CODE_ERROR,data); }
static struct json_object *jmx_api_dhcp_reservation_delete(struct json_object *req_obj)
{ const char *id="",*lan_id=""; struct json_object *v=NULL,*data=json_object_new_object(); if(req_obj&&json_object_object_get_ex(req_obj,"id",&v)&&v)id=json_object_get_string(v); if(req_obj&&json_object_object_get_ex(req_obj,"lan_id",&v)&&v)lan_id=json_object_get_string(v); int rc=jmx_dhcp_reservation_delete(id); int arc=(rc==0&&lan_id[0])?jmx_dhcp_service_apply(lan_id):0; json_object_object_add(data,"ok",json_object_new_boolean(rc==0&&arc==0)); return jmx_gen_api_response_data((rc==0&&arc==0)?API_CODE_SUCCESS:API_CODE_ERROR,data); }

/* UPnP IGD aliases for jmx common API */
static struct json_object *jmx_api_upnp_service_get(struct json_object *req_obj)
{
    (void)req_obj;
    return jmx_upnp_service_get();
}

static struct json_object *jmx_api_upnp_service_set(struct json_object *req_obj)
{
    return jmx_upnp_service_save_apply_result(req_obj);
}

static struct json_object *jmx_api_upnp_acl_set(struct json_object *req_obj)
{
    return jmx_upnp_acl_save_apply_result(req_obj);
}

static struct json_object *jmx_api_upnp_acl_delete(struct json_object *req_obj)
{
    const char *id = ""; struct json_object *v = NULL;
    if (req_obj && json_object_object_get_ex(req_obj, "id", &v) && v) id = json_object_get_string(v);
    return jmx_upnp_acl_delete_apply_result(id);
}

static struct json_object *jmx_api_upnp_mapping_delete(struct json_object *req_obj)
{
    const char *id = ""; struct json_object *v = NULL; struct json_object *data = json_object_new_object();
    if (req_obj && json_object_object_get_ex(req_obj, "id", &v) && v) id = json_object_get_string(v);
    int rc = jmx_upnp_mapping_delete(id);
    json_object_object_add(data, "ok", json_object_new_boolean(rc == 0));
    return jmx_gen_api_response_data(rc == 0 ? API_CODE_SUCCESS : API_CODE_ERROR, data);
}

/* DNS service aliases for jmx common API */
static struct json_object *jmx_api_dns_service_get(struct json_object *req_obj)
{
    (void)req_obj;
    return jmx_dns_service_get();
}

static struct json_object *jmx_api_dns_service_set(struct json_object *req_obj)
{
    return jmx_dns_service_save_apply_result(req_obj, 1);
}

static struct json_object *jmx_api_dns_direct_write_disabled(struct json_object *req_obj)
{
    (void)req_obj;
    struct json_object *data = json_object_new_object();
    json_object_object_add(data, "ok", json_object_new_boolean(0));
    json_object_object_add(data, "error", json_object_new_string("capability_disabled"));
    json_object_object_add(data, "capability", json_object_new_string("dns_bulk_transaction"));
    json_object_object_add(data, "persisted", json_object_new_boolean(0));
    json_object_object_add(data, "applied", json_object_new_boolean(0));
    json_object_object_add(data, "reason",
                           json_object_new_string("complete_dns_snapshot_required_for_rollback"));
    return jmx_gen_api_response_data(API_CODE_ERROR, data);
}


static struct json_object *jmx_api_system_settings_get_wrap(struct json_object *req_obj)
{
    (void)req_obj;
    return jmx_system_settings_get();
}

static struct json_object *jmx_api_system_settings_set_wrap(struct json_object *req_obj)
{
    return jmx_system_settings_save_apply_result(req_obj);
}

static struct json_object *jmx_api_system_settings_apply_wrap(struct json_object *req_obj)
{
    return jmx_system_settings_apply_result(req_obj);
}

static struct json_object *jmx_api_system_kernel_restore_wrap(struct json_object *req_obj)
{
    return jmx_system_kernel_restore_defaults(req_obj);
}

static struct json_object *jmx_api_system_service_set_wrap(struct json_object *req_obj)
{
    return jmx_system_service_set(req_obj);
}

static struct json_object *jmx_api_system_cron_set_wrap(struct json_object *req_obj)
{
    struct json_object *data = json_object_new_object();
    int rc = jmx_system_cron_set(req_obj);
    json_object_object_add(data, "ok", json_object_new_boolean(rc == 0));
    return jmx_gen_api_response_data(rc == 0 ? API_CODE_SUCCESS : API_CODE_ERROR, data);
}



static struct json_object *jmx_api_signature_db_status_wrap(struct json_object *req_obj){return jmx_signature_db_status(req_obj);}
static struct json_object *jmx_api_signature_db_apps_wrap(struct json_object *req_obj){return jmx_signature_db_apps(req_obj);}
static struct json_object *jmx_api_signature_db_rules_wrap(struct json_object *req_obj){return jmx_signature_db_rules(req_obj);}
static struct json_object *jmx_api_signature_db_carriers_wrap(struct json_object *req_obj){return jmx_signature_db_carriers(req_obj);}
static struct json_object *jmx_api_signature_db_carrier_prefixes_wrap(struct json_object *req_obj){return jmx_signature_db_carrier_prefixes(req_obj);}
static struct json_object *jmx_api_signature_db_domain_groups_wrap(struct json_object *req_obj){return jmx_signature_db_domain_groups(req_obj);}
static struct json_object *jmx_api_signature_db_domains_wrap(struct json_object *req_obj){return jmx_signature_db_domains(req_obj);}
static struct json_object *jmx_api_signature_db_device_vendors_wrap(struct json_object *req_obj){return jmx_signature_db_device_vendors(req_obj);}
static struct json_object *jmx_api_signature_db_device_types_wrap(struct json_object *req_obj){return jmx_signature_db_device_types(req_obj);}
static struct json_object *jmx_api_signature_db_fingerprint_rules_wrap(struct json_object *req_obj){return jmx_signature_db_fingerprint_rules(req_obj);}
static struct json_object *jmx_api_signature_resolve_app_wrap(struct json_object *req_obj){return jmx_signature_db_resolve_app(req_obj);}
static struct json_object *jmx_api_signature_update_validate_wrap(struct json_object *req_obj){return jmx_signature_update_validate(req_obj);}
static struct json_object *jmx_api_signature_update_apply_wrap(struct json_object *req_obj){return jmx_signature_update_apply(req_obj);}
static struct json_object *jmx_api_signature_update_status_wrap(struct json_object *req_obj){return jmx_signature_update_status(req_obj);}
static struct json_object *jmx_api_system_disabled_functions_get_wrap(struct json_object *req_obj){(void)req_obj;return jmx_system_disabled_functions_get();}
static struct json_object *jmx_api_system_disabled_functions_set_wrap(struct json_object *req_obj){return jmx_system_disabled_functions_set(req_obj);}
static struct json_object *jmx_api_system_services_status_wrap(struct json_object *req_obj){return jmx_system_services_status(req_obj);}
static struct json_object *jmx_api_system_mounts_status_wrap(struct json_object *req_obj){return jmx_system_mounts_status(req_obj);}
static struct json_object *jmx_api_system_cron_get_wrap(struct json_object *req_obj){return jmx_system_cron_get(req_obj);}
static struct json_object *jmx_api_wifi_capabilities_get_wrap(struct json_object *req_obj){return jmx_wifi_capabilities_get(req_obj);}
static struct json_object *jmx_api_cellular_runtime_status_wrap(struct json_object *req_obj){return jmx_cellular_runtime_status(req_obj);}
static struct json_object *jmx_api_runtime_pending_matrix_wrap(struct json_object *req_obj){return jmx_runtime_pending_matrix(req_obj);}
static struct json_object *jmx_api_jmxd_phase_summary_wrap(struct json_object *req_obj){return jmx_jmxd_phase_summary(req_obj);}
static struct json_object *jmx_api_work_mode_get_wrap(struct json_object *req_obj){(void)req_obj;return dw_work_mode_get(NULL);}
static struct json_object *jmx_api_work_mode_preview_wrap(struct json_object *req_obj){return dw_work_mode_preview(req_obj);}
static struct json_object *jmx_api_work_mode_apply_wrap(struct json_object *req_obj){return dw_work_mode_apply(req_obj);}
static struct json_object *jmx_api_work_mode_rollback_wrap(struct json_object *req_obj){return dw_work_mode_rollback(req_obj);}
static struct json_object *jmx_api_dreamingwrt_line_load_wrap(struct json_object *req_obj)
{
    dw_refresh_wan_state();
    return jmx_db_api_line_load(req_obj);
}
static struct json_object *jmx_api_dreamingwrt_line_health_wrap(struct json_object *req_obj)
{
    dw_refresh_wan_state();
    return jmx_db_api_line_health(req_obj);
}
static struct json_object *jmx_api_dreamingwrt_system_health_wrap(struct json_object *req_obj)
{
    dw_refresh_wan_state();
    return jmx_db_api_system_health(req_obj);
}
static struct json_object *jmx_api_dreamingwrt_wifi_config_wrap(struct json_object *req_obj){(void)req_obj;return jmx_wifi_config_get();}
static struct json_object *jmx_api_dreamingwrt_log_center_wrap(struct json_object *req_obj){(void)req_obj;return jmx_log_center_get();}

static jmx_api_node_t jmx_api_node_list[] = {
    {"get_dashboard_common", jmx_api_get_dashboard_common},
    {"get_hourly_top_apps", jmx_api_get_hourly_top_apps},
    {"get_daily_top_apps", jmx_api_get_daily_top_apps},
    {"delete_record_files", jmx_api_delete_record_files},
    {"get_global_app_type_stats", jmx_api_get_global_app_type_stats},
    {"get_global_traffic_stats", jmx_api_get_global_traffic_stats},
    {"get_daily_top_users", jmx_api_get_daily_top_users},
    {"get_active_users", jmx_api_get_active_users},
    {"get_filter_rules", jmx_api_get_filter_rules},
    {"add_filter_rule", jmx_api_add_filter_rule},
    {"update_filter_rule", jmx_api_update_filter_rule},
    {"delete_filter_rule", jmx_api_delete_filter_rule},
    {"get_user_basic_info", jmx_api_get_user_basic_info},
    {"get_online_offline_records", jmx_api_get_online_offline_records},
    {"get_appfilter_whitelist", jmx_api_get_appfilter_whitelist},
    {"add_appfilter_whitelist", jmx_api_add_appfilter_whitelist},
    {"del_appfilter_whitelist", jmx_api_del_appfilter_whitelist},
    {"get_app_filter_adv", jmx_api_get_app_filter_adv},
    {"set_app_filter_adv", jmx_api_set_app_filter_adv},
    {"get_system_info", jmx_api_get_system_info},
    {"set_system_info", jmx_api_set_system_info},
    {"get_mac_filter_rules", jmx_api_get_mac_filter_rules},
    {"add_mac_filter_rule", jmx_api_add_mac_filter_rule},
    {"update_mac_filter_rule", jmx_api_update_mac_filter_rule},
    {"delete_mac_filter_rule", jmx_api_delete_mac_filter_rule},
    {"get_mac_filter_whitelist", jmx_api_get_mac_filter_whitelist},
    {"add_mac_filter_whitelist", jmx_api_add_mac_filter_whitelist},
    {"del_mac_filter_whitelist", jmx_api_del_mac_filter_whitelist},
    {"get_mac_filter_adv", jmx_api_get_mac_filter_adv},
    {"set_mac_filter_adv", jmx_api_set_mac_filter_adv},
    {"get_record_base", jmx_api_get_record_base},
    {"set_record_base", jmx_api_set_record_base},
    {"record_action", jmx_api_record_action},
    {"get_lan_list", jmx_api_get_lan_list},
    {"add_lan", jmx_api_add_lan},
    {"mod_lan", jmx_api_mod_lan},
    {"del_lan", jmx_api_del_lan},
    {"get_wan_list", jmx_api_get_wan_list},
    {"add_wan", jmx_api_add_wan},
    {"mod_wan", jmx_api_mod_wan},
    {"del_wan", jmx_api_del_wan},
    {"get_lan_info", jmx_api_get_lan_info},
    {"set_lan_info", jmx_api_set_lan_info},
    {"get_wan_info", jmx_api_get_wan_info},
    {"set_wan_info", jmx_api_set_wan_info},
    {"get_work_mode", jmx_api_get_work_mode},
    {"set_work_mode", jmx_api_set_work_mode},
    {"set_nickname", jmx_api_set_nickname},
    {"dev_visit_list", jmx_api_dev_visit_list},
    {"dev_visit_time", jmx_api_dev_visit_time},
    {"app_class_visit_time", jmx_api_app_class_visit_time},
    {"dev_list", jmx_api_dev_list},
    {"class_list", jmx_api_class_list},
    {"get_all_users", jmx_api_get_all_users},
    {"get_oaf_status", jmx_api_get_oaf_status},
    {"visit_list", jmx_api_visit_list},
    {"get_device_list", jmx_api_get_device_list},
    {"get_dashboard_param", jmx_api_get_dashboard_param},
    {"set_dashboard_param", jmx_api_set_dashboard_param},

    {"get_domain_stats", jmx_api_get_domain_stats},
    {"get_hosttype_stats", jmx_api_get_hosttype_stats},
    {"get_dpi_stats", jmx_api_get_dpi_stats},
    {"reload_rules", jmx_api_reload_rules},
    {"route_wan_register", jmx_api_route_wan_register},
    {"route_wan_unregister", jmx_api_route_wan_unregister},
    {"route_wan_health", jmx_api_route_wan_health},
    {"route_rule_add", jmx_api_route_rule_add},
    {"route_rule_del", jmx_api_route_rule_del},
    {"route_rule_flush", jmx_api_route_rule_flush},
    {"route_rule_clear_hits", jmx_api_route_rule_clear_hits},
    {"route_status", jmx_api_route_status},
    {"route_reload", jmx_api_route_reload},
    {"route_config_get", jmx_api_route_config_get},
    {"route_config_set", jmx_api_route_config_set},
    {"get_user_records", jmx_api_get_user_records},
    {"get_history_session", jmx_api_get_history_session},
    {"get_feature_info", jmx_api_get_feature_info},
    {"get_feature_class_list", jmx_api_get_feature_class_list},
    {"line_health", jmx_api_dreamingwrt_line_health_wrap},
    {"dreamingwrt_line_load", jmx_api_dreamingwrt_line_load_wrap},
    {"dreamingwrt_line_health", jmx_api_dreamingwrt_line_health_wrap},
    {"dreamingwrt_wifi_config", jmx_api_dreamingwrt_wifi_config_wrap},
    {"dreamingwrt_log_center", jmx_api_dreamingwrt_log_center_wrap},
    {"dreamingwrt_ipv6_load", jmx_db_api_ipv6_load},
    {"dreamingwrt_vpn_status", jmx_db_api_vpn_status},
    {"dreamingwrt_client_detail", jmx_db_api_client_detail},
    {"dreamingwrt_system_health", jmx_api_dreamingwrt_system_health_wrap},
    {"dreamingwrt_lan_config", jmx_db_api_lan_config},
    {"dreamingwrt_firewall_service", jmx_api_firewall_service_get},
    {"dreamingwrt_firewall_service_set", jmx_api_firewall_service_set},
    {"dreamingwrt_firewall_service_apply", jmx_api_firewall_service_apply},
    {"dreamingwrt_flow_control", jmx_api_flow_control_get},
    {"dreamingwrt_flow_control_save", jmx_api_flow_control_set},
    {"dreamingwrt_flow_control_apply", jmx_api_flow_control_apply},
    {"dreamingwrt_flow_control_rule_test", jmx_api_flow_control_rule_test},
    {"dreamingwrt_vpn_config", jmx_api_vpn_config_get},
    {"dreamingwrt_vpn_config_set", jmx_api_vpn_config_set},
    {"dreamingwrt_vpn_config_apply", jmx_api_vpn_config_apply},
    {"dreamingwrt_vpn_server_set", jmx_api_vpn_server_set},
    {"dreamingwrt_vpn_client_set", jmx_api_vpn_client_set},
    {"dreamingwrt_vpn_site_set", jmx_api_vpn_site_set},
    {"dreamingwrt_vpn_account_set", jmx_api_vpn_account_set},
    {"dreamingwrt_vpn_certificate_set", jmx_api_vpn_certificate_set},

    {"dreamingwrt_bulk_ip", jmx_api_bulk_ip_get},
    {"dreamingwrt_bulk_ip_set", jmx_api_bulk_ip_set},
    {"dreamingwrt_bulk_ip_import", jmx_api_bulk_ip_import},
    {"dreamingwrt_bulk_ip_export", jmx_api_bulk_ip_export},
    {"dreamingwrt_multicast_service", jmx_api_multicast_service_get},
    {"dreamingwrt_multicast_service_set", jmx_api_multicast_service_set},
    {"dreamingwrt_multicast_service_apply", jmx_api_multicast_service_apply},
    {"dreamingwrt_dns_service", jmx_api_dns_service_get},
    {"dreamingwrt_dns_service_set", jmx_api_dns_service_set},
    {"dreamingwrt_dns_upstream_set", jmx_api_dns_direct_write_disabled},
    {"dreamingwrt_dns_rule_set", jmx_api_dns_direct_write_disabled},
    {"dreamingwrt_dns_rule_delete", jmx_api_dns_direct_write_disabled},
    {"dreamingwrt_upnp_service", jmx_api_upnp_service_get},
    {"dreamingwrt_upnp_service_set", jmx_api_upnp_service_set},
    {"dreamingwrt_upnp_acl_set", jmx_api_upnp_acl_set},
    {"dreamingwrt_upnp_acl_delete", jmx_api_upnp_acl_delete},
    {"dreamingwrt_upnp_mapping_delete", jmx_api_upnp_mapping_delete},
    {"dreamingwrt_dhcp_service", jmx_api_dhcp_service_get},
    {"dreamingwrt_dhcp_service_set", jmx_api_dhcp_service_set},
    {"dreamingwrt_dhcp_reservation_delete", jmx_api_dhcp_reservation_delete},
    {"dreamingwrt_topology_flow", jmx_api_dreamingwrt_topology_flow},
    {"dreamingwrt_network_global_get", jmx_api_net_global_get},
    {"dreamingwrt_network_global_set", jmx_api_net_global_set},
    {"dreamingwrt_physical_port_list", jmx_api_physical_port_list},
    {"dreamingwrt_physical_port_refresh", jmx_api_physical_port_refresh},
    {"dreamingwrt_radius_list", jmx_api_radius_list},
    {"dreamingwrt_radius_set", jmx_api_radius_set},
    {"dreamingwrt_radius_delete", jmx_api_radius_delete},
    {"dreamingwrt_hybrid_line_list", jmx_api_hybrid_line_list},
    {"dreamingwrt_hybrid_line_set", jmx_api_hybrid_line_set},
    {"dreamingwrt_hybrid_line_add", jmx_api_hybrid_line_set},
    {"dreamingwrt_hybrid_line_delete", jmx_api_hybrid_line_delete},
    {"dreamingwrt_hybrid_line_enable", jmx_api_hybrid_line_enable},
    {"dreamingwrt_system_settings", jmx_api_system_settings_get_wrap},
    {"dreamingwrt_system_settings_get", jmx_api_system_settings_get_wrap},
    {"dreamingwrt_system_settings_set", jmx_api_system_settings_set_wrap},
    {"dreamingwrt_system_settings_apply", jmx_api_system_settings_apply_wrap},
    {"dreamingwrt_system_kernel_restore_defaults", jmx_api_system_kernel_restore_wrap},

    {"dreamingwrt_service_set", jmx_api_system_service_set_wrap},
    {"dreamingwrt_cron_set", jmx_api_system_cron_set_wrap},
    {"dreamingwrt_system_disabled_functions_get", jmx_api_system_disabled_functions_get_wrap},
    {"dreamingwrt_system_disabled_functions_set", jmx_api_system_disabled_functions_set_wrap},
    {"dreamingwrt_system_services_status", jmx_api_system_services_status_wrap},
    {"dreamingwrt_system_mounts_status", jmx_api_system_mounts_status_wrap},
    {"dreamingwrt_system_cron_get", jmx_api_system_cron_get_wrap},
    {"dreamingwrt_signature_db_status", jmx_api_signature_db_status_wrap},
    {"dreamingwrt_signature_db_apps", jmx_api_signature_db_apps_wrap},
    {"dreamingwrt_signature_db_rules", jmx_api_signature_db_rules_wrap},
    {"dreamingwrt_signature_db_carriers", jmx_api_signature_db_carriers_wrap},
    {"dreamingwrt_signature_db_carrier_prefixes", jmx_api_signature_db_carrier_prefixes_wrap},
    {"dreamingwrt_signature_db_domain_groups", jmx_api_signature_db_domain_groups_wrap},
    {"dreamingwrt_signature_db_domains", jmx_api_signature_db_domains_wrap},
    {"dreamingwrt_signature_db_device_vendors", jmx_api_signature_db_device_vendors_wrap},
    {"dreamingwrt_signature_db_device_types", jmx_api_signature_db_device_types_wrap},
    {"dreamingwrt_signature_db_fingerprint_rules", jmx_api_signature_db_fingerprint_rules_wrap},
    {"dreamingwrt_signature_resolve_app", jmx_api_signature_resolve_app_wrap},
    {"dreamingwrt_signature_update_validate", jmx_api_signature_update_validate_wrap},
    {"dreamingwrt_signature_update_apply", jmx_api_signature_update_apply_wrap},
    {"dreamingwrt_signature_update_status", jmx_api_signature_update_status_wrap},
    {"dreamingwrt_wifi_capabilities_get", jmx_api_wifi_capabilities_get_wrap},
    {"dreamingwrt_cellular_runtime_status", jmx_api_cellular_runtime_status_wrap},
    {"dreamingwrt_runtime_pending_matrix", jmx_api_runtime_pending_matrix_wrap},
    {"dreamingwrt_jmxd_phase_summary", jmx_api_jmxd_phase_summary_wrap},
    {"dreamingwrt_work_mode_get", jmx_api_work_mode_get_wrap},
    {"dreamingwrt_work_mode_preview", jmx_api_work_mode_preview_wrap},
    {"dreamingwrt_work_mode_apply", jmx_api_work_mode_apply_wrap},
    {"dreamingwrt_work_mode_rollback", jmx_api_work_mode_rollback_wrap},

    {NULL, NULL}
};

int ubus_handle_common(struct ubus_context *ctx, struct ubus_object *obj, struct ubus_request_data *req, 
                        const char *method, struct blob_attr *msg) {
    int i = 0;
    jmx_api_node_t *api_node = NULL;
    LOG_DEBUG("method: %s\n", method);
    char *msg_obj_str = blobmsg_format_json(msg, true);
    if (!msg_obj_str) 
        return 0;
    LOG_INFO("msg_obj_str: %s\n", msg_obj_str);
    struct json_object *req_obj = json_tokener_parse(msg_obj_str);
    LOG_DEBUG("req_obj: %s\n", json_object_to_json_string(req_obj));
    if (!req_obj) {
        LOG_ERROR("Failed to parse JSON request\n");
        ubus_response_json(ctx, req, jmx_gen_api_response_data(API_CODE_ERROR, NULL));
        free(msg_obj_str);
        return 0;
    }
    const char *api_name = NULL;
    struct json_object *api_obj = json_object_object_get(req_obj, "api");
    if (api_obj) {
        api_name = json_object_get_string(api_obj);
        if (api_name && api_name[0]) {
            char tracked_method[160];
            snprintf(tracked_method, sizeof(tracked_method), "common:%s", api_name);
            jmx_core_ubus_dispatch_update_current("jmx", tracked_method);
        }
    } else {
        LOG_ERROR("api_obj is NULL\n");
        struct json_object *error_response = jmx_gen_api_response_data(API_CODE_ERROR, NULL);
        ubus_response_json(ctx, req, error_response);
        json_object_put(error_response);
        json_object_put(req_obj);
        free(msg_obj_str);
        return 0;
    }
    

    struct json_object *data_obj = json_object_object_get(req_obj, "data");
    if (!data_obj) {
        data_obj = req_obj;
    }


    for (i = 0; i < sizeof(jmx_api_node_list) / sizeof(jmx_api_node_t); i++) {

        if (jmx_api_node_list[i].api_name == NULL) {
            break;
        }
        if (strcmp(jmx_api_node_list[i].api_name, api_name) == 0) {
            api_node = &jmx_api_node_list[i];
            LOG_DEBUG("found api_node: %s\n", api_node->api_name);
            break;
        }
    }
    struct json_object *response_obj = NULL;
    if (api_node && api_node->handler) {
        response_obj = api_node->handler(data_obj);
        if (response_obj) {
            ubus_response_json(ctx, req, response_obj);
        } else {
            LOG_ERROR("Handler returned NULL for API: %s\n", api_name);
            response_obj = jmx_gen_api_response_data(API_CODE_ERROR, NULL);
            ubus_response_json(ctx, req, response_obj);
        }
    }
    else {
        LOG_WARN("API not found: %s\n", api_name);
        response_obj = jmx_gen_api_response_data(API_CODE_ERROR, NULL);
        ubus_response_json(ctx, req, response_obj);
    }
    
    if (response_obj) {
        json_object_put(response_obj);
    }
    json_object_put(req_obj);
    free(msg_obj_str);
    return 0;
}

static const struct blobmsg_policy def_policy[1] = {

};


int ubus_handle_common(struct ubus_context *ctx, struct ubus_object *obj, struct ubus_request_data *req, 
                        const char *method, struct blob_attr *msg);


/* ── Audit log ubus handler ── */

#define JMX_AUDIT_QUERY_EVENT_BUDGET 4096U

enum {
	AUDIT_MAX_EVENTS,
	AUDIT_MAX_EVENTS_MAX
};

static const struct blobmsg_policy audit_policy[] = {
	[AUDIT_MAX_EVENTS] = { .name = "max_events", .type = BLOBMSG_TYPE_INT32 },
};

static int handle_audit(struct ubus_context *ctx, struct ubus_object *obj,
			struct ubus_request_data *req, const char *method,
			struct blob_attr *msg)
{
	struct blob_attr *tb[AUDIT_MAX_EVENTS_MAX];
	int max_events = 32;
	size_t buf_size;
	char *buf;

	blobmsg_parse(audit_policy, AUDIT_MAX_EVENTS_MAX, tb, blob_data(msg), blob_len(msg));
	if (tb[AUDIT_MAX_EVENTS])
		max_events = blobmsg_get_u32(tb[AUDIT_MAX_EVENTS]);
	if (max_events < 1) max_events = 1;
	if (max_events > 256) max_events = 256;

	if ((size_t)max_events > (((size_t)-1) - 2) / JMX_AUDIT_QUERY_EVENT_BUDGET) {
		blob_buf_init(&b, 0);
		blobmsg_add_string(&b, "error", "too_many_events");
		return ubus_send_reply(ctx, req, b.head);
	}
	buf_size = (size_t)max_events * JMX_AUDIT_QUERY_EVENT_BUDGET + 2;

	buf = malloc(buf_size);
	if (!buf) {
		blob_buf_init(&b, 0);
		blobmsg_add_string(&b, "error", "oom");
		return ubus_send_reply(ctx, req, b.head);
	}

	jmx_audit_query_json(buf, buf_size, max_events);

	blob_buf_init(&b, 0);
	blobmsg_add_u64(&b, "total", jmx_audit_total_events());
	blobmsg_add_u64(&b, "dropped", jmx_audit_dropped_events());
	/* events is a JSON string, caller can parse */
		if (buf && buf[0]) {
			/* Trim to just add as info */
			blobmsg_add_string(&b, "events_json", buf);
		}

	free(buf);
	return ubus_send_reply(ctx, req, b.head);
}


static struct ubus_method jmx_object_methods[] = {
    UBUS_METHOD("common", ubus_handle_common, def_policy),
    UBUS_METHOD("debug", handle_debug, def_policy),
    UBUS_METHOD("audit", handle_audit, audit_policy),
};

static ubus_handler_t jmx_object_original_handlers[ARRAY_SIZE(jmx_object_methods)];

static int jmx_core_dispatch_jmx_method(struct ubus_context *ctx, struct ubus_object *obj,
                                        struct ubus_request_data *req, const char *method,
                                        struct blob_attr *msg)
{
    size_t i;
    uint64_t call_id = jmx_core_ubus_dispatch_enter("jmx", method);
    int rc = UBUS_STATUS_METHOD_NOT_FOUND;

    for (i = 0; i < ARRAY_SIZE(jmx_object_methods); i++) {
        if (jmx_object_methods[i].name && !strcmp(jmx_object_methods[i].name, method) &&
            jmx_object_original_handlers[i]) {
            rc = jmx_object_original_handlers[i](ctx, obj, req, method, msg);
            break;
        }
    }

    jmx_core_ubus_dispatch_leave(call_id, rc);
    return rc;
}


static struct ubus_object_type jmx_object_type =
    UBUS_OBJECT_TYPE("jmx", jmx_object_methods);


static struct ubus_object jmx_object = {
    .name = "jmx",
    .type = &jmx_object_type,
    .methods = jmx_object_methods,
    .n_methods = ARRAY_SIZE(jmx_object_methods),
};

static int jmx_add_object(struct ubus_object *obj)
{
    int ret = ubus_add_object(ubus_ctx, obj);
    if (ret != 0)
        LOG_ERROR("Failed to publish object '%s': %s\n", obj->name, ubus_strerror(ret));
    return ret;
}

static void jmx_object_install_dispatcher(void)
{
    size_t i;

    for (i = 0; i < ARRAY_SIZE(jmx_object_methods); i++) {
        if (!jmx_object_original_handlers[i])
            jmx_object_original_handlers[i] = jmx_object_methods[i].handler;
        jmx_object_methods[i].handler = jmx_core_dispatch_jmx_method;
    }
}

static int jmx_ubus_register_objects(void)
{
    if (!ubus_ctx)
        return -1;
    jmx_object_install_dispatcher();
    if (jmx_add_object(&jmx_object) != 0)
        return -1;
    if (dreamingwrt_ubus_register(ubus_ctx) != 0) {
        ubus_remove_object(ubus_ctx, &jmx_object);
        return -1;
    }
    return 0;
}

static void jmx_ubus_unregister_objects(void)
{
    if (!ubus_ctx)
        return;
    dreamingwrt_ubus_unregister(ubus_ctx);
    if (jmx_object.id)
        ubus_remove_object(ubus_ctx, &jmx_object);
}

static void jmx_ubus_cleanup_at_exit(void)
{
    if (!ubus_ctx)
        return;
    jmx_ubus_unregister_objects();
    ubus_free(ubus_ctx);
    ubus_ctx = NULL;
}

static void jmx_ubus_add_uloop(void)
{
    if (!ubus_ctx)
        return;
    ubus_add_uloop(ubus_ctx);
}

static int jmx_ubus_reconnect_now(void)
{
    int rc;

    if (!ubus_ctx)
        return -1;
    rc = ubus_reconnect(ubus_ctx, jmx_ubus_path_primary);
    if (rc != 0)
        rc = ubus_reconnect(ubus_ctx, jmx_ubus_path_fallback);
    if (rc != 0) {
        LOG_ERROR("ubus reconnect failed: %s\n", ubus_strerror(rc));
        return rc;
    }
    ubus_ctx->connection_lost = jmx_ubus_connection_lost;
    /*
     * Re-arm the freshly reconnected socket in uloop BEFORE object
     * registration.  ubus_reconnect() opened a new socket fd but left it
     * outside the epoll set; object registration below issues synchronous
     * request/response round-trips on that fd.  If registration failed and we
     * returned early (the previous behaviour), the live ubus fd was never
     * added to uloop, so the main loop stayed idle in epoll_wait while every
     * inbound method invoke hung forever (ubus list still worked from the
     * cached registration).  Adding the socket first guarantees the control
     * plane is serviceable and lets the reconnect timer retry registration on
     * its own cadence instead of orphaning the connection.
     */
    jmx_ubus_add_uloop();
    if (jmx_ubus_register_objects() != 0) {
        LOG_ERROR("ubus reconnected but object registration failed; will retry\n");
        return -1;
    }
    LOG_WARN("ubus reconnected and objects re-registered\n");
    return 0;
}

static void jmx_ubus_reconnect_cb(struct uloop_timeout *t)
{
    (void)t;
    if (jmx_ubus_reconnect_now() != 0)
        uloop_timeout_set(&jmx_ubus_reconnect_timer, 2000);
}

static void jmx_ubus_connection_lost(struct ubus_context *ctx)
{
    LOG_ERROR("ubus connection lost; scheduling reconnect\n");
    if (ctx)
        uloop_fd_delete(&ctx->sock);
    if (!jmx_ubus_reconnect_timer.pending)
        uloop_timeout_set(&jmx_ubus_reconnect_timer, 2000);
}

/*
 * Self-healing control-plane watchdog.  The observer-only core watchdog only
 * detects a stalled/livelocked main loop; it cannot see the specific failure
 * where the loop is healthy (heartbeat fires) but the ubus socket has fallen
 * out of the epoll set after a reconnect edge case.  In that state the object
 * stays registered on ubusd yet no inbound invoke is ever read, so every
 * dreamingwrt method times out.  This lightweight timer re-arms the socket if
 * it observes a live fd that is no longer registered in uloop, closing that
 * gap without ever touching ubus from a foreign thread.
 */
#ifndef JMX_UBUS_HEALTH_INTERVAL_MS
#define JMX_UBUS_HEALTH_INTERVAL_MS 5000
#endif
static void jmx_ubus_health_cb(struct uloop_timeout *t)
{
    if (ubus_ctx && ubus_ctx->sock.fd >= 0 && !ubus_ctx->sock.registered &&
        !jmx_ubus_reconnect_timer.pending) {
        LOG_ERROR("ubus socket fd=%d present but not registered in uloop; "
                  "re-arming control plane\n", ubus_ctx->sock.fd);
        jmx_ubus_add_uloop();
    }
    uloop_timeout_set(t, JMX_UBUS_HEALTH_INTERVAL_MS);
}

int jmx_ubus_init(void)
{
    LOG_INFO("jmx ubus init...\n");
    jmx_ubus_reconnect_timer.cb = jmx_ubus_reconnect_cb;
	ubus_ctx = ubus_connect("/var/run/ubus/ubus.sock");
    if (!ubus_ctx){
		ubus_ctx = ubus_connect("/var/run/ubus.sock");
	}
	if (!ubus_ctx){
        LOG_ERROR("Failed to connect to ubus\n");
		return -EIO;
	}

    ubus_ctx->connection_lost = jmx_ubus_connection_lost;
    if (jmx_ubus_register_objects() != 0) {
        ubus_free(ubus_ctx);
        ubus_ctx = NULL;
        return -EIO;
    }
    jmx_ubus_add_uloop();
    jmx_ubus_health_timer.cb = jmx_ubus_health_cb;
    uloop_timeout_set(&jmx_ubus_health_timer, JMX_UBUS_HEALTH_INTERVAL_MS);
    atexit(jmx_ubus_cleanup_at_exit);
    return 0;
}
