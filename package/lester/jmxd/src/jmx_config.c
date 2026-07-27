// SPDX-License-Identifier: GPL-2.0-or-later
/* 
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>  
*/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include "jmx_config.h"
#include "jmx.h"
#include "jmx_signature_db.h"
#include "jmx_netconfig_db.h"
#include "jmx_system_data_path.h"
#include <sqlite3.h>
#include <unistd.h>
#include <uci.h>

static app_name_info_t *app_name_table = NULL;
static char (*g_class_name_table)[MAX_CLASS_NAME_LEN] = NULL;
char (*CLASS_NAME_TABLE)[MAX_CLASS_NAME_LEN] = NULL;

int g_app_count = 0;
int g_cur_class_num = 0;
int g_app_name_table_capacity = 0;
int g_class_name_capacity = 0;

static int config_signature_db_path(char *path, size_t path_len)
{
    enum jmx_system_db_source source;
    char error[64];

    if (jmx_system_db_resolve(JMX_SYSTEM_DB_SIGNATURE, path, path_len,
                              &source, error, sizeof(error)) == 0)
        return 0;
    LOG_ERROR("signature DB resolve failed: %s\n", error);
    return -1;
}

void free_app_name_table(void)
{
    free(app_name_table);
    app_name_table = NULL;
    g_app_count = 0;
    g_app_name_table_capacity = 0;
}

void free_app_class_name_table(void)
{
    free(g_class_name_table);
    g_class_name_table = NULL;
    CLASS_NAME_TABLE = NULL;
    g_cur_class_num = 0;
    g_class_name_capacity = 0;
}

char *get_app_name_by_id(int id)
{
    int i;

    if (!app_name_table || g_app_count <= 0)
        return "";

    for (i = 0; i < g_app_count; i++)
    {
        if (id == app_name_table[i].id)
            return app_name_table[i].name;
    }
    return "";
}

void init_app_name_table(void)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *st = NULL;
    char signature_path[512] = {0};
    int expected_count = 0;
    int rc;

    free_app_name_table();
    if (config_signature_db_path(signature_path, sizeof(signature_path)) != 0 ||
        sqlite3_open_v2(signature_path, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK)
        goto failed;
    if (sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM app WHERE enabled=1", -1, &st, NULL) != SQLITE_OK ||
        sqlite3_step(st) != SQLITE_ROW)
        goto failed;
    expected_count = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    st = NULL;
    if (expected_count <= 0)
        goto failed;
    app_name_table = calloc(expected_count, sizeof(*app_name_table));
    if (!app_name_table)
        goto failed;
    g_app_name_table_capacity = expected_count;
    if (sqlite3_prepare_v2(db,
            "SELECT app_id,name FROM app WHERE enabled=1 ORDER BY app_id",
            -1, &st, NULL) != SQLITE_OK)
        goto failed;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        const char *name = (const char *)sqlite3_column_text(st, 1);
        if (g_app_count >= g_app_name_table_capacity)
            goto failed;
        app_name_table[g_app_count].id = sqlite3_column_int(st, 0);
        snprintf(app_name_table[g_app_count].name,
                 sizeof(app_name_table[g_app_count].name), "%s", name ? name : "");
        g_app_count++;
    }
    if (rc != SQLITE_DONE)
        goto failed;
    sqlite3_finalize(st);
    sqlite3_close(db);
    LOG_WARN("signature app name table loaded: count=%d capacity=%d\n",
             g_app_count, g_app_name_table_capacity);
    return;

failed:
    sqlite3_finalize(st);
    if (db)
        sqlite3_close(db);
    LOG_ERROR("cannot initialize app names from %s\n", signature_path);
    free_app_name_table();
}

void init_app_class_name_table(void)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *st = NULL;
    char signature_path[512] = {0};
    int max_class_id = 0;
    int rc;

    free_app_class_name_table();
    if (config_signature_db_path(signature_path, sizeof(signature_path)) != 0 ||
        sqlite3_open_v2(signature_path, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK)
        goto failed;
    if (sqlite3_prepare_v2(db,
            "SELECT COALESCE(MAX(category_id),0) FROM app_category WHERE category_id<=?1",
            -1, &st, NULL) != SQLITE_OK)
        goto failed;
    sqlite3_bind_int(st, 1, MAX_APP_TYPE);
    if (sqlite3_step(st) != SQLITE_ROW)
        goto failed;
    max_class_id = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    st = NULL;
    if (max_class_id <= 0)
        goto failed;
    g_class_name_table = calloc(MAX_APP_TYPE, sizeof(*g_class_name_table));
    if (!g_class_name_table)
        goto failed;
    CLASS_NAME_TABLE = g_class_name_table;
    g_class_name_capacity = MAX_APP_TYPE;
    if (sqlite3_prepare_v2(db,
            "SELECT category_id,name FROM app_category WHERE category_id BETWEEN 1 AND ?1 ORDER BY category_id",
            -1, &st, NULL) != SQLITE_OK)
        goto failed;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        int category_id = sqlite3_column_int(st, 0);
        const char *name = (const char *)sqlite3_column_text(st, 1);
        snprintf(g_class_name_table[category_id - 1], MAX_CLASS_NAME_LEN,
                 "%s", name ? name : "");
    }
    if (rc != SQLITE_DONE)
        goto failed;
    g_cur_class_num = max_class_id;
    sqlite3_finalize(st);
    sqlite3_close(db);
    LOG_WARN("signature class table loaded: max_id=%d capacity=%d\n",
             g_cur_class_num, g_class_name_capacity);
    return;

failed:
    sqlite3_finalize(st);
    if (db)
        sqlite3_close(db);
    LOG_ERROR("cannot initialize app categories from %s\n", signature_path);
    free_app_class_name_table();
}

int check_time_valid(char *t)
{
    if (!t)
        return 0;
    if (strlen(t) < 3 || strlen(t) > 5 || (!strstr(t, ":")))
        return 0;
    else
        return 1;
}


int config_get_appfilter_enable(void)
{
    return jmx_network_control_appfilter_enabled();
}

int config_get_lan_ip(char *lan_ip, int len)
{
    int ret = 0;
    struct uci_context *ctx = uci_alloc_context();
    if (!ctx)
        return -1;
    ret = jmx_uci_get_value(ctx, "network.lan.ipaddr", lan_ip, len);
    uci_free_context(ctx);
    return ret;
}

int config_get_lan_mask(char *lan_mask, int len)
{
    int ret = 0;
    struct uci_context *ctx = uci_alloc_context();
    if (!ctx)
        return -1;
    ret = jmx_uci_get_value(ctx, "network.lan.netmask", lan_mask, len);
    uci_free_context(ctx);
    return ret;
}
