#include <string.h>
#include <sqlite3.h>
#include "jmx_huginn.h"
#include "jmx.h"   /* for LOG_ERROR */

#define HUGINN_DB_PATH "/etc/dreamingwrt/huginn_muninn.db"

static sqlite3 *g_huginn_db = NULL;
static int g_huginn_tried = 0;

void huginn_init(void)
{
    if (g_huginn_tried) return;
    g_huginn_tried = 1;
    if (sqlite3_open_v2(HUGINN_DB_PATH, &g_huginn_db,
            SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
        /* silent - file may not exist */
        if (g_huginn_db)
            sqlite3_close(g_huginn_db);
        g_huginn_db = NULL;
    }
}

void huginn_close(void)
{
    if (g_huginn_db) { sqlite3_close(g_huginn_db); g_huginn_db = NULL; }
    g_huginn_tried = 0;
}

static int huginn_query(const char *sql_col, const char *key, huginn_result_t *out)
{
    if (!g_huginn_db || !key || !key[0] || !out) return -1;

    char sql[512];
    snprintf(sql, sizeof(sql),
        "SELECT d.name, c.device_type, c.device_vendor "
        "FROM dhcp_combinations c "
        "LEFT JOIN device d ON d.id = c.device_id "
        "WHERE c.%s = ?1 LIMIT 1", sql_col);

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(g_huginn_db, sql, -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, key, -1, SQLITE_TRANSIENT);

    int rc = -1;
    if (sqlite3_step(st) == SQLITE_ROW) {
        const char *name = (const char *)sqlite3_column_text(st, 0);
        const char *type = (const char *)sqlite3_column_text(st, 1);
        const char *vendor = (const char *)sqlite3_column_text(st, 2);
        if (name && name[0]) {
            snprintf(out->device_name, sizeof(out->device_name), "%s", name);
            snprintf(out->device_type, sizeof(out->device_type), "%s", type ? type : "");
            snprintf(out->device_vendor, sizeof(out->device_vendor), "%s", vendor ? vendor : "");
            rc = 0;
        }
    }
    sqlite3_finalize(st);
    return rc;
}

int huginn_lookup_by_option55(const char *option55, huginn_result_t *out)
{
    return huginn_query("dhcp_option55", option55, out);
}

int huginn_lookup_by_vendor_class(const char *vendor_class, huginn_result_t *out)
{
    /* vendor_class is not in dhcp_combinations table directly,
     * but we can try matching against satori_name or device_vendor */
    if (!g_huginn_db || !vendor_class || !vendor_class[0] || !out) return -1;

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(g_huginn_db,
        "SELECT d.name, c.device_type, c.device_vendor "
        "FROM dhcp_combinations c "
        "LEFT JOIN device d ON d.id = c.device_id "
        "WHERE c.device_vendor LIKE '%' || ?1 || '%' "
        "ORDER BY length(c.device_vendor) ASC LIMIT 1",
        -1, &st, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_text(st, 1, vendor_class, -1, SQLITE_TRANSIENT);

    int rc = -1;
    if (sqlite3_step(st) == SQLITE_ROW) {
        const char *name = (const char *)sqlite3_column_text(st, 0);
        const char *type = (const char *)sqlite3_column_text(st, 1);
        const char *vendor = (const char *)sqlite3_column_text(st, 2);
        if (name && name[0]) {
            snprintf(out->device_name, sizeof(out->device_name), "%s", name);
            snprintf(out->device_type, sizeof(out->device_type), "%s", type ? type : "");
            snprintf(out->device_vendor, sizeof(out->device_vendor), "%s", vendor ? vendor : "");
            rc = 0;
        }
    }
    sqlite3_finalize(st);
    return rc;
}
