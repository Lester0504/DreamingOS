// SPDX-License-Identifier: GPL-2.0-or-later
#include "flowd_internal.h"
#include "flowd_nft_apply.h"
#include "flowd_runtime_contract.h"
#include "jmx_system_data_path.h"

#define WORKER_STATUS_VERSION "1.0"

static int flowd_exec(sqlite3 *db, const char *sql)
{
    char *err = NULL;
    int rc;

    if (!db || !sql)
        return -1;
    rc = sqlite3_exec(db, sql, NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[dreamingwrt-flowd] sqlite exec failed: %s sql=%s\n",
                err ? err : sqlite3_errmsg(db), sql);
        sqlite3_free(err);
        return -1;
    }
    return 0;
}

static struct json_object *flowd_sqlite_text_json(sqlite3_stmt *st, int col)
{
    const char *s = st ? (const char *)sqlite3_column_text(st, col) : NULL;

    return json_object_new_string(s ? s : "");
}

static void flowd_response_set_ok(struct json_object *resp, int ok)
{
    if (!resp)
        return;
    json_object_object_del(resp, "ok");
    json_object_object_add(resp, "ok", json_object_new_boolean(ok));
}

static void flowd_settings_defaults(struct flowd_settings *out)
{
    if (!out)
        return;
    memset(out, 0, sizeof(*out));
    out->enabled = 1;
    snprintf(out->geoip_dir, sizeof(out->geoip_dir), "%s", FLOWD_DEFAULT_GEOIP_DIR);
    snprintf(out->runtime_dir, sizeof(out->runtime_dir), "%s", FLOWD_DEFAULT_RUNTIME_DIR);
    snprintf(out->apply_mode, sizeof(out->apply_mode), "%s", "plan-only");
}

static void flowd_status_error_add(struct json_object *errors, const char *field,
                                   const char *code)
{
    struct json_object *o;

    if (!errors)
        return;
    o = json_object_new_object();
    json_object_object_add(o, "field", json_object_new_string(field ? field : ""));
    json_object_object_add(o, "code", json_object_new_string(code ? code : "query_failed"));
    json_object_array_add(errors, o);
}

sqlite3_stmt *flowd_config_prepare(const char *sql)
{
    sqlite3_stmt *st = NULL;

    if (!g_flowd_config_db || !sql)
        return NULL;
    if (sqlite3_prepare_v2(g_flowd_config_db, sql, -1, &st, NULL) != SQLITE_OK) {
        fprintf(stderr, "[dreamingwrt-flowd] config sqlite prepare failed: %s sql=%s\n",
                sqlite3_errmsg(g_flowd_config_db), sql);
        return NULL;
    }
    return st;
}

static int flowd_db_init_fail(void)
{
    if (g_flowd_config_db) {
        sqlite3_close(g_flowd_config_db);
        g_flowd_config_db = NULL;
    }
    return -1;
}

int flowd_db_init(void)
{
    if (g_flowd_config_db)
        return 0;
    if (flowd_mkdir_p(FLOWD_DEFAULT_GEOIP_DIR, 0755) != 0) {
        fprintf(stderr, "[dreamingwrt-flowd] create %s failed\n", FLOWD_DEFAULT_GEOIP_DIR);
        return -1;
    }
    if (sqlite3_open(FLOWD_CONFIG_DB_PATH, &g_flowd_config_db) != SQLITE_OK) {
        fprintf(stderr, "[dreamingwrt-flowd] open %s failed\n", FLOWD_CONFIG_DB_PATH);
        return flowd_db_init_fail();
    }
    sqlite3_busy_timeout(g_flowd_config_db, 3000);
    if (flowd_exec(g_flowd_config_db, "PRAGMA journal_mode=WAL") != 0 ||
        flowd_exec(g_flowd_config_db, "PRAGMA foreign_keys=ON") != 0)
        return flowd_db_init_fail();

    if (flowd_exec(g_flowd_config_db,
        "CREATE TABLE IF NOT EXISTS flowd_settings ("
        " id INTEGER PRIMARY KEY CHECK(id=1),"
        " enabled INTEGER NOT NULL DEFAULT 1,"
        " geoip_dir TEXT NOT NULL DEFAULT '/etc/dreamingwrt/geoip',"
        " runtime_dir TEXT NOT NULL DEFAULT '/etc/dreamingwrt/geoip/runtime',"
        " apply_mode TEXT NOT NULL DEFAULT 'plan-only',"
        " updated_at INTEGER NOT NULL DEFAULT 0)") != 0)
        return flowd_db_init_fail();
    if (flowd_exec(g_flowd_config_db,
        "INSERT OR IGNORE INTO flowd_settings(id,enabled,geoip_dir,runtime_dir,apply_mode,updated_at) "
        "VALUES(1,1,'/etc/dreamingwrt/geoip','/etc/dreamingwrt/geoip/runtime','plan-only',0)") != 0)
        return flowd_db_init_fail();
    if (flowd_exec(g_flowd_config_db,
        "UPDATE flowd_settings SET apply_mode='plan-only' WHERE apply_mode<>'plan-only'") != 0)
        return flowd_db_init_fail();

    if (flowd_exec(g_flowd_config_db,
        "CREATE TABLE IF NOT EXISTS flowd_geoip_sources ("
        " id TEXT PRIMARY KEY,"
        " name TEXT NOT NULL DEFAULT '',"
        " type TEXT NOT NULL DEFAULT 'maxmind-mmdb',"
        " path TEXT NOT NULL DEFAULT '',"
        " edition TEXT NOT NULL DEFAULT '',"
        " enabled INTEGER NOT NULL DEFAULT 1,"
        " auto_update INTEGER NOT NULL DEFAULT 0,"
        " license_ref TEXT NOT NULL DEFAULT '',"
        " meta_json TEXT NOT NULL DEFAULT '{}',"
        " created_at INTEGER NOT NULL DEFAULT 0,"
        " updated_at INTEGER NOT NULL DEFAULT 0,"
        " last_import_at INTEGER NOT NULL DEFAULT 0,"
        " last_import_status TEXT NOT NULL DEFAULT 'never',"
        " last_error TEXT NOT NULL DEFAULT '')") != 0)
        return flowd_db_init_fail();
    if (flowd_exec(g_flowd_config_db,
        "INSERT OR IGNORE INTO flowd_geoip_sources"
        "(id,name,type,path,edition,enabled,auto_update,license_ref,meta_json,created_at,updated_at) "
        "VALUES('local-geolite2','Local GeoLite2 Country','maxmind-mmdb',"
        "'/etc/dreamingwrt/geoip/GeoLite2-Country.mmdb','GeoLite2-Country',1,0,'','{}',0,0)") != 0)
        return flowd_db_init_fail();
    if (flowd_exec(g_flowd_config_db,
        "INSERT OR IGNORE INTO flowd_geoip_sources"
        "(id,name,type,path,edition,enabled,auto_update,license_ref,meta_json,created_at,updated_at) "
        "VALUES('p3terx-geolite2-country','P3TERX GeoLite2 Country','github-mmdb',"
        "'/etc/dreamingwrt/geoip/GeoLite2-Country.mmdb','GeoLite2-Country',1,1,'',"
        "'{\"url\":\"https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb\",\"repo\":\"P3TERX/GeoLite.mmdb\",\"asset\":\"GeoLite2-Country.mmdb\"}',0,0)") != 0)
        return flowd_db_init_fail();

    if (flowd_exec(g_flowd_config_db,
        "CREATE TABLE IF NOT EXISTS flowd_country_policies ("
        " id TEXT PRIMARY KEY,"
        " name TEXT NOT NULL DEFAULT '',"
        " enabled INTEGER NOT NULL DEFAULT 1,"
        " priority INTEGER NOT NULL DEFAULT 1000,"
        " direction TEXT NOT NULL DEFAULT 'dst',"
        " countries_json TEXT NOT NULL DEFAULT '[]',"
        " action TEXT NOT NULL DEFAULT 'route',"
        " target TEXT NOT NULL DEFAULT '',"
        " family TEXT NOT NULL DEFAULT 'both',"
        " remark TEXT NOT NULL DEFAULT '',"
        " created_at INTEGER NOT NULL DEFAULT 0,"
        " updated_at INTEGER NOT NULL DEFAULT 0)") != 0)
        return flowd_db_init_fail();
    if (flowd_exec(g_flowd_config_db,
        "CREATE INDEX IF NOT EXISTS idx_flowd_country_policies_priority "
        "ON flowd_country_policies(enabled,priority,id)") != 0)
        return flowd_db_init_fail();

    if (flowd_exec(g_flowd_config_db,
        "CREATE TABLE IF NOT EXISTS flowd_objects ("
        " id TEXT PRIMARY KEY,"
        " type TEXT NOT NULL DEFAULT 'ipv4',"
        " name TEXT NOT NULL DEFAULT '',"
        " enabled INTEGER NOT NULL DEFAULT 1,"
        " value_json TEXT NOT NULL DEFAULT '[]',"
        " remark TEXT NOT NULL DEFAULT '',"
        " created_at INTEGER NOT NULL DEFAULT 0,"
        " updated_at INTEGER NOT NULL DEFAULT 0)") != 0)
        return flowd_db_init_fail();
    if (flowd_exec(g_flowd_config_db,
        "CREATE INDEX IF NOT EXISTS idx_flowd_objects_type "
        "ON flowd_objects(enabled,type,id)") != 0)
        return flowd_db_init_fail();

    if (flowd_exec(g_flowd_config_db,
        "CREATE TABLE IF NOT EXISTS flowd_custom_protocols ("
        " id TEXT PRIMARY KEY,"
        " name TEXT NOT NULL DEFAULT '',"
        " enabled INTEGER NOT NULL DEFAULT 1,"
        " priority INTEGER NOT NULL DEFAULT 1000,"
        " kind TEXT NOT NULL DEFAULT 'l4',"
        " proto TEXT NOT NULL DEFAULT 'tcp',"
        " src_port TEXT NOT NULL DEFAULT '',"
        " dst_port TEXT NOT NULL DEFAULT '',"
        " match_json TEXT NOT NULL DEFAULT '{}',"
        " tags_json TEXT NOT NULL DEFAULT '[]',"
        " remark TEXT NOT NULL DEFAULT '',"
        " created_at INTEGER NOT NULL DEFAULT 0,"
        " updated_at INTEGER NOT NULL DEFAULT 0)") != 0)
        return flowd_db_init_fail();
    if (flowd_exec(g_flowd_config_db,
        "CREATE INDEX IF NOT EXISTS idx_flowd_custom_protocols_priority "
        "ON flowd_custom_protocols(enabled,priority,id)") != 0)
        return flowd_db_init_fail();
    if (flowd_exec(g_flowd_config_db,
        "CREATE INDEX IF NOT EXISTS idx_flowd_custom_protocols_kind "
        "ON flowd_custom_protocols(enabled,kind,id)") != 0)
        return flowd_db_init_fail();

    if (flowd_exec(g_flowd_config_db,
        "CREATE TABLE IF NOT EXISTS flowd_route_groups ("
        " id TEXT PRIMARY KEY,"
        " name TEXT NOT NULL DEFAULT '',"
        " enabled INTEGER NOT NULL DEFAULT 1,"
        " mode TEXT NOT NULL DEFAULT 'weighted',"
        " hash TEXT NOT NULL DEFAULT 'src_ip,dst_ip,dst_port',"
        " health_check INTEGER NOT NULL DEFAULT 1,"
        " failback INTEGER NOT NULL DEFAULT 1,"
        " remark TEXT NOT NULL DEFAULT '',"
        " created_at INTEGER NOT NULL DEFAULT 0,"
        " updated_at INTEGER NOT NULL DEFAULT 0)") != 0)
        return flowd_db_init_fail();
    if (flowd_exec(g_flowd_config_db,
        "CREATE TABLE IF NOT EXISTS flowd_route_group_members ("
        " id TEXT PRIMARY KEY,"
        " group_id TEXT NOT NULL,"
        " target TEXT NOT NULL DEFAULT '',"
        " weight INTEGER NOT NULL DEFAULT 100,"
        " role TEXT NOT NULL DEFAULT 'active',"
        " priority INTEGER NOT NULL DEFAULT 100,"
        " meta_json TEXT NOT NULL DEFAULT '{}',"
        " sort_order INTEGER NOT NULL DEFAULT 0,"
        " FOREIGN KEY(group_id) REFERENCES flowd_route_groups(id) ON DELETE CASCADE)") != 0)
        return flowd_db_init_fail();
    if (flowd_exec(g_flowd_config_db,
        "CREATE INDEX IF NOT EXISTS idx_flowd_route_groups_enabled "
        "ON flowd_route_groups(enabled,mode,id)") != 0)
        return flowd_db_init_fail();
    if (flowd_exec(g_flowd_config_db,
        "CREATE INDEX IF NOT EXISTS idx_flowd_route_group_members_group "
        "ON flowd_route_group_members(group_id,sort_order,id)") != 0)
        return flowd_db_init_fail();

    if (flowd_exec(g_flowd_config_db,
        "CREATE TABLE IF NOT EXISTS flowd_wan_capacity ("
        " id TEXT PRIMARY KEY,"
        " name TEXT NOT NULL DEFAULT '',"
        " enabled INTEGER NOT NULL DEFAULT 1,"
        " wan TEXT NOT NULL UNIQUE,"
        " down_kbps INTEGER NOT NULL DEFAULT 0,"
        " up_kbps INTEGER NOT NULL DEFAULT 0,"
        " headroom_pct INTEGER NOT NULL DEFAULT 95,"
        " scheduler TEXT NOT NULL DEFAULT 'cake',"
        " link_layer TEXT NOT NULL DEFAULT 'ethernet',"
        " overhead_bytes INTEGER NOT NULL DEFAULT 0,"
        " ingress INTEGER NOT NULL DEFAULT 1,"
        " egress INTEGER NOT NULL DEFAULT 1,"
        " source TEXT NOT NULL DEFAULT 'manual',"
        " remark TEXT NOT NULL DEFAULT '',"
        " created_at INTEGER NOT NULL DEFAULT 0,"
        " updated_at INTEGER NOT NULL DEFAULT 0)") != 0)
        return flowd_db_init_fail();
    if (flowd_exec(g_flowd_config_db,
        "CREATE INDEX IF NOT EXISTS idx_flowd_wan_capacity_enabled "
        "ON flowd_wan_capacity(enabled,wan,id)") != 0)
        return flowd_db_init_fail();

    if (flowd_exec(g_flowd_config_db,
        "CREATE TABLE IF NOT EXISTS flowd_wan_health ("
        " id TEXT PRIMARY KEY,"
        " name TEXT NOT NULL DEFAULT '',"
        " enabled INTEGER NOT NULL DEFAULT 1,"
        " wan TEXT NOT NULL DEFAULT '',"
        " method TEXT NOT NULL DEFAULT 'icmp',"
        " targets_json TEXT NOT NULL DEFAULT '[]',"
        " interval_s INTEGER NOT NULL DEFAULT 5,"
        " timeout_ms INTEGER NOT NULL DEFAULT 1000,"
        " loss_threshold_pct INTEGER NOT NULL DEFAULT 50,"
        " latency_threshold_ms INTEGER NOT NULL DEFAULT 300,"
        " fail_count INTEGER NOT NULL DEFAULT 3,"
        " recover_count INTEGER NOT NULL DEFAULT 2,"
        " remark TEXT NOT NULL DEFAULT '',"
        " created_at INTEGER NOT NULL DEFAULT 0,"
        " updated_at INTEGER NOT NULL DEFAULT 0)") != 0)
        return flowd_db_init_fail();
    if (flowd_exec(g_flowd_config_db,
        "CREATE INDEX IF NOT EXISTS idx_flowd_wan_health_wan "
        "ON flowd_wan_health(enabled,wan,id)") != 0)
        return flowd_db_init_fail();

    if (flowd_exec(g_flowd_config_db,
        "CREATE TABLE IF NOT EXISTS flowd_split_rules ("
        " id TEXT PRIMARY KEY,"
        " name TEXT NOT NULL DEFAULT '',"
        " enabled INTEGER NOT NULL DEFAULT 1,"
        " priority INTEGER NOT NULL DEFAULT 1000,"
        " action TEXT NOT NULL DEFAULT 'route',"
        " target_group TEXT NOT NULL DEFAULT '',"
        " fallback TEXT NOT NULL DEFAULT 'main',"
        " family TEXT NOT NULL DEFAULT 'both',"
        " src_object TEXT NOT NULL DEFAULT '',"
        " dst_object TEXT NOT NULL DEFAULT '',"
        " app_object TEXT NOT NULL DEFAULT '',"
        " service_object TEXT NOT NULL DEFAULT '',"
        " time_object TEXT NOT NULL DEFAULT '',"
        " proto TEXT NOT NULL DEFAULT 'any',"
        " src_port TEXT NOT NULL DEFAULT '',"
        " dst_port TEXT NOT NULL DEFAULT '',"
        " match_json TEXT NOT NULL DEFAULT '{}',"
        " remark TEXT NOT NULL DEFAULT '',"
        " created_at INTEGER NOT NULL DEFAULT 0,"
        " updated_at INTEGER NOT NULL DEFAULT 0)") != 0)
        return flowd_db_init_fail();
    if (flowd_exec(g_flowd_config_db,
        "CREATE INDEX IF NOT EXISTS idx_flowd_split_rules_priority "
        "ON flowd_split_rules(enabled,priority,id)") != 0)
        return flowd_db_init_fail();
    if (flowd_exec(g_flowd_config_db,
        "CREATE INDEX IF NOT EXISTS idx_flowd_split_rules_target "
        "ON flowd_split_rules(target_group,enabled,priority,id)") != 0)
        return flowd_db_init_fail();

    if (flowd_exec(g_flowd_config_db,
        "CREATE TABLE IF NOT EXISTS flowd_domain_rules ("
        " id TEXT PRIMARY KEY,"
        " name TEXT NOT NULL DEFAULT '',"
        " enabled INTEGER NOT NULL DEFAULT 1,"
        " priority INTEGER NOT NULL DEFAULT 1000,"
        " action TEXT NOT NULL DEFAULT 'route',"
        " domain_object TEXT NOT NULL DEFAULT '',"
        " src_object TEXT NOT NULL DEFAULT '',"
        " time_object TEXT NOT NULL DEFAULT '',"
        " route_group TEXT NOT NULL DEFAULT '',"
        " fallback TEXT NOT NULL DEFAULT 'main',"
        " family TEXT NOT NULL DEFAULT 'both',"
        " mark TEXT NOT NULL DEFAULT '',"
        " log_event INTEGER NOT NULL DEFAULT 1,"
        " remark TEXT NOT NULL DEFAULT '',"
        " created_at INTEGER NOT NULL DEFAULT 0,"
        " updated_at INTEGER NOT NULL DEFAULT 0)") != 0)
        return flowd_db_init_fail();
    if (flowd_exec(g_flowd_config_db,
        "CREATE INDEX IF NOT EXISTS idx_flowd_domain_rules_priority "
        "ON flowd_domain_rules(enabled,priority,id)") != 0)
        return flowd_db_init_fail();
    if (flowd_exec(g_flowd_config_db,
        "CREATE INDEX IF NOT EXISTS idx_flowd_domain_rules_domain "
        "ON flowd_domain_rules(domain_object,enabled,priority,id)") != 0)
        return flowd_db_init_fail();

    if (flowd_exec(g_flowd_config_db,
        "CREATE TABLE IF NOT EXISTS flowd_qos_settings ("
        " id INTEGER PRIMARY KEY CHECK(id=1),"
        " enabled INTEGER NOT NULL DEFAULT 0,"
        " scheduler TEXT NOT NULL DEFAULT 'htb',"
        " default_class TEXT NOT NULL DEFAULT 'normal',"
        " unknown_class TEXT NOT NULL DEFAULT 'normal',"
        " headroom_pct INTEGER NOT NULL DEFAULT 95,"
        " diffserv INTEGER NOT NULL DEFAULT 1,"
        " ack_filter INTEGER NOT NULL DEFAULT 0,"
        " fairness TEXT NOT NULL DEFAULT 'per_host',"
        " remark TEXT NOT NULL DEFAULT '',"
        " updated_at INTEGER NOT NULL DEFAULT 0)") != 0)
        return flowd_db_init_fail();
    if (flowd_exec(g_flowd_config_db,
        "INSERT OR IGNORE INTO flowd_qos_settings"
        "(id,enabled,scheduler,default_class,unknown_class,headroom_pct,diffserv,ack_filter,fairness,remark,updated_at) "
        "VALUES(1,0,'htb','normal','normal',95,1,0,'per_host','',0)") != 0)
        return flowd_db_init_fail();

    if (flowd_exec(g_flowd_config_db,
        "CREATE TABLE IF NOT EXISTS flowd_qos_classes ("
        " id TEXT PRIMARY KEY,"
        " name TEXT NOT NULL DEFAULT '',"
        " enabled INTEGER NOT NULL DEFAULT 1,"
        " priority INTEGER NOT NULL DEFAULT 100,"
        " guarantee_pct INTEGER NOT NULL DEFAULT 0,"
        " ceiling_pct INTEGER NOT NULL DEFAULT 100,"
        " latency_ms INTEGER NOT NULL DEFAULT 0,"
        " dscp TEXT NOT NULL DEFAULT '',"
        " color TEXT NOT NULL DEFAULT '',"
        " remark TEXT NOT NULL DEFAULT '',"
        " created_at INTEGER NOT NULL DEFAULT 0,"
        " updated_at INTEGER NOT NULL DEFAULT 0)") != 0)
        return flowd_db_init_fail();
    if (flowd_exec(g_flowd_config_db,
        "CREATE INDEX IF NOT EXISTS idx_flowd_qos_classes_priority "
        "ON flowd_qos_classes(enabled,priority,id)") != 0)
        return flowd_db_init_fail();
    if (flowd_exec(g_flowd_config_db,
        "INSERT OR IGNORE INTO flowd_qos_classes"
        "(id,name,enabled,priority,guarantee_pct,ceiling_pct,latency_ms,dscp,color,remark,created_at,updated_at) "
        "VALUES('realtime','Realtime',1,100,10,100,30,'EF','','default realtime class',0,0),"
        "('interactive','Interactive',1,200,5,100,80,'AF41','','default interactive class',0,0),"
        "('normal','Normal',1,300,0,100,0,'','','default normal class',0,0),"
        "('bulk','Bulk',1,900,0,80,0,'CS1','','default bulk class',0,0)") != 0)
        return flowd_db_init_fail();

    if (flowd_exec(g_flowd_config_db,
        "CREATE TABLE IF NOT EXISTS flowd_qos_rules ("
        " id TEXT PRIMARY KEY,"
        " name TEXT NOT NULL DEFAULT '',"
        " enabled INTEGER NOT NULL DEFAULT 1,"
        " priority INTEGER NOT NULL DEFAULT 1000,"
        " class_id TEXT NOT NULL DEFAULT '',"
        " direction TEXT NOT NULL DEFAULT 'both',"
        " family TEXT NOT NULL DEFAULT 'both',"
        " interface TEXT NOT NULL DEFAULT '',"
        " src_object TEXT NOT NULL DEFAULT '',"
        " dst_object TEXT NOT NULL DEFAULT '',"
        " app_object TEXT NOT NULL DEFAULT '',"
        " service_object TEXT NOT NULL DEFAULT '',"
        " time_object TEXT NOT NULL DEFAULT '',"
        " rate_kbps INTEGER NOT NULL DEFAULT 0,"
        " ceil_kbps INTEGER NOT NULL DEFAULT 0,"
        " per_host INTEGER NOT NULL DEFAULT 0,"
        " match_json TEXT NOT NULL DEFAULT '{}',"
        " remark TEXT NOT NULL DEFAULT '',"
        " created_at INTEGER NOT NULL DEFAULT 0,"
        " updated_at INTEGER NOT NULL DEFAULT 0)") != 0)
        return flowd_db_init_fail();
    if (flowd_exec(g_flowd_config_db,
        "CREATE INDEX IF NOT EXISTS idx_flowd_qos_rules_priority "
        "ON flowd_qos_rules(enabled,priority,id)") != 0)
        return flowd_db_init_fail();
    if (flowd_exec(g_flowd_config_db,
        "CREATE INDEX IF NOT EXISTS idx_flowd_qos_rules_class "
        "ON flowd_qos_rules(class_id,enabled,priority,id)") != 0)
        return flowd_db_init_fail();

    if (flowd_exec(g_flowd_config_db,
        "CREATE TABLE IF NOT EXISTS flowd_smart_qos_categories ("
        " id TEXT PRIMARY KEY,"
        " name TEXT NOT NULL DEFAULT '',"
        " enabled INTEGER NOT NULL DEFAULT 1,"
        " category TEXT NOT NULL UNIQUE,"
        " priority INTEGER NOT NULL DEFAULT 500,"
        " qos_class TEXT NOT NULL DEFAULT '',"
        " latency_target_ms INTEGER NOT NULL DEFAULT 0,"
        " remark TEXT NOT NULL DEFAULT '',"
        " created_at INTEGER NOT NULL DEFAULT 0,"
        " updated_at INTEGER NOT NULL DEFAULT 0)") != 0)
        return flowd_db_init_fail();
    if (flowd_exec(g_flowd_config_db,
        "CREATE INDEX IF NOT EXISTS idx_flowd_smart_qos_categories_priority "
        "ON flowd_smart_qos_categories(enabled,priority,category)") != 0)
        return flowd_db_init_fail();

    if (flowd_exec(g_flowd_config_db,
        "CREATE TABLE IF NOT EXISTS flowd_quota_rules ("
        " id TEXT PRIMARY KEY,"
        " name TEXT NOT NULL DEFAULT '',"
        " enabled INTEGER NOT NULL DEFAULT 1,"
        " priority INTEGER NOT NULL DEFAULT 1000,"
        " scope TEXT NOT NULL DEFAULT 'daily',"
        " action TEXT NOT NULL DEFAULT 'throttle',"
        " target_object TEXT NOT NULL DEFAULT '',"
        " limit_bytes INTEGER NOT NULL DEFAULT 0,"
        " reset_hour INTEGER NOT NULL DEFAULT 0,"
        " timezone TEXT NOT NULL DEFAULT 'local',"
        " throttle_class TEXT NOT NULL DEFAULT '',"
        " notify INTEGER NOT NULL DEFAULT 1,"
        " log_event INTEGER NOT NULL DEFAULT 1,"
        " remark TEXT NOT NULL DEFAULT '',"
        " created_at INTEGER NOT NULL DEFAULT 0,"
        " updated_at INTEGER NOT NULL DEFAULT 0)") != 0)
        return flowd_db_init_fail();
    if (flowd_exec(g_flowd_config_db,
        "CREATE INDEX IF NOT EXISTS idx_flowd_quota_rules_priority "
        "ON flowd_quota_rules(enabled,priority,id)") != 0)
        return flowd_db_init_fail();
    if (flowd_exec(g_flowd_config_db,
        "CREATE INDEX IF NOT EXISTS idx_flowd_quota_rules_target "
        "ON flowd_quota_rules(target_object,enabled,priority,id)") != 0)
        return flowd_db_init_fail();

    if (flowd_exec(g_flowd_config_db,
        "CREATE TABLE IF NOT EXISTS flowd_conn_limit_rules ("
        " id TEXT PRIMARY KEY,"
        " name TEXT NOT NULL DEFAULT '',"
        " enabled INTEGER NOT NULL DEFAULT 1,"
        " priority INTEGER NOT NULL DEFAULT 1000,"
        " scope TEXT NOT NULL DEFAULT 'per_host',"
        " action TEXT NOT NULL DEFAULT 'reject_new',"
        " src_object TEXT NOT NULL DEFAULT '',"
        " dst_object TEXT NOT NULL DEFAULT '',"
        " service_object TEXT NOT NULL DEFAULT '',"
        " time_object TEXT NOT NULL DEFAULT '',"
        " proto TEXT NOT NULL DEFAULT 'any',"
        " conn_limit INTEGER NOT NULL DEFAULT 0,"
        " burst INTEGER NOT NULL DEFAULT 0,"
        " log_event INTEGER NOT NULL DEFAULT 1,"
        " remark TEXT NOT NULL DEFAULT '',"
        " created_at INTEGER NOT NULL DEFAULT 0,"
        " updated_at INTEGER NOT NULL DEFAULT 0)") != 0)
        return flowd_db_init_fail();
    if (flowd_exec(g_flowd_config_db,
        "CREATE INDEX IF NOT EXISTS idx_flowd_conn_limit_rules_priority "
        "ON flowd_conn_limit_rules(enabled,priority,id)") != 0)
        return flowd_db_init_fail();

    if (flowd_exec(g_flowd_config_db,
        "CREATE TABLE IF NOT EXISTS flowd_app_rules ("
        " id TEXT PRIMARY KEY,"
        " name TEXT NOT NULL DEFAULT '',"
        " enabled INTEGER NOT NULL DEFAULT 1,"
        " priority INTEGER NOT NULL DEFAULT 1000,"
        " action TEXT NOT NULL DEFAULT 'mark',"
        " src_object TEXT NOT NULL DEFAULT '',"
        " app_object TEXT NOT NULL DEFAULT '',"
        " time_object TEXT NOT NULL DEFAULT '',"
        " route_group TEXT NOT NULL DEFAULT '',"
        " qos_class TEXT NOT NULL DEFAULT '',"
        " mark TEXT NOT NULL DEFAULT '',"
        " log_event INTEGER NOT NULL DEFAULT 1,"
        " remark TEXT NOT NULL DEFAULT '',"
        " created_at INTEGER NOT NULL DEFAULT 0,"
        " updated_at INTEGER NOT NULL DEFAULT 0)") != 0)
        return flowd_db_init_fail();
    if (flowd_exec(g_flowd_config_db,
        "CREATE INDEX IF NOT EXISTS idx_flowd_app_rules_priority "
        "ON flowd_app_rules(enabled,priority,id)") != 0)
        return flowd_db_init_fail();

    if (flowd_exec(g_flowd_config_db,
        "CREATE TABLE IF NOT EXISTS flowd_apply_jobs ("
        " id TEXT PRIMARY KEY,"
        " kind TEXT NOT NULL DEFAULT 'compile',"
        " requested_by TEXT NOT NULL DEFAULT '',"
        " state TEXT NOT NULL DEFAULT 'compiled',"
        " dry_run INTEGER NOT NULL DEFAULT 1,"
        " plan_path TEXT NOT NULL DEFAULT '',"
        " plan_json TEXT NOT NULL DEFAULT '{}',"
        " error TEXT NOT NULL DEFAULT '',"
        " created_at INTEGER NOT NULL DEFAULT 0,"
        " updated_at INTEGER NOT NULL DEFAULT 0,"
        " completed_at INTEGER NOT NULL DEFAULT 0)") != 0)
        return flowd_db_init_fail();
    if (flowd_exec(g_flowd_config_db,
        "CREATE INDEX IF NOT EXISTS idx_flowd_apply_jobs_created "
        "ON flowd_apply_jobs(created_at,state)") != 0)
        return flowd_db_init_fail();
    return 0;
}

void flowd_db_close(void)
{
    if (g_flowd_config_db) {
        sqlite3_close(g_flowd_config_db);
        g_flowd_config_db = NULL;
    }
}

int flowd_settings_load(struct flowd_settings *out)
{
    sqlite3_stmt *st;
    int rc;

    if (!out)
        return -1;
    flowd_settings_defaults(out);
    st = flowd_config_prepare("SELECT enabled,geoip_dir,runtime_dir,apply_mode FROM flowd_settings WHERE id=1");
    if (!st)
        return -1;
    rc = sqlite3_step(st);
    if (rc != SQLITE_ROW) {
        if (rc != SQLITE_DONE)
            fprintf(stderr, "[dreamingwrt-flowd] settings query failed: %s\n",
                    g_flowd_config_db ? sqlite3_errmsg(g_flowd_config_db) : "database unavailable");
        sqlite3_finalize(st);
        return -1;
    }
    out->enabled = sqlite3_column_int(st, 0);
    snprintf(out->geoip_dir, sizeof(out->geoip_dir), "%s",
             sqlite3_column_text(st, 1) ? (const char *)sqlite3_column_text(st, 1) : FLOWD_DEFAULT_GEOIP_DIR);
    snprintf(out->runtime_dir, sizeof(out->runtime_dir), "%s",
             sqlite3_column_text(st, 2) ? (const char *)sqlite3_column_text(st, 2) : FLOWD_DEFAULT_RUNTIME_DIR);
    snprintf(out->apply_mode, sizeof(out->apply_mode), "%s",
             sqlite3_column_text(st, 3) ? (const char *)sqlite3_column_text(st, 3) : "plan-only");
    sqlite3_finalize(st);
    return 0;
}

static int flowd_count_sql_checked(const char *sql, int *ok)
{
    sqlite3_stmt *st;
    int count = 0;
    int rc;

    if (ok)
        *ok = 0;

    st = flowd_config_prepare(sql);
    if (!st)
        return 0;
    rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) {
        count = sqlite3_column_int(st, 0);
        if (ok)
            *ok = 1;
    } else if (rc != SQLITE_DONE) {
        fprintf(stderr, "[dreamingwrt-flowd] count query failed: %s sql=%s\n",
                g_flowd_config_db ? sqlite3_errmsg(g_flowd_config_db) : "database unavailable",
                sql ? sql : "");
    }
    sqlite3_finalize(st);
    return count;
}

static int flowd_count_sql(const char *sql)
{
    int ok = 0;

    return flowd_count_sql_checked(sql, &ok);
}

static int flowd_collect_rows(sqlite3_stmt *st, struct json_object *arr,
                              void (*row_fn)(struct json_object *, sqlite3_stmt *),
                              const char *label)
{
    int rc;

    if (!st || !arr || !row_fn)
        return 0;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW)
        row_fn(arr, st);
    if (rc != SQLITE_DONE) {
        fprintf(stderr, "[dreamingwrt-flowd] %s query failed: %s\n",
                label ? label : "list",
                g_flowd_config_db ? sqlite3_errmsg(g_flowd_config_db) : "database unavailable");
        return 0;
    }
    return 1;
}

static void flowd_list_total_add(struct json_object *resp, int *ok, const char **error,
                                 const char *sql, const char *error_code)
{
    int total_ok = 0;
    int total = flowd_count_sql_checked(sql, &total_ok);

    json_object_object_add(resp, "total", json_object_new_int(total));
    if (!total_ok) {
        if (ok)
            *ok = 0;
        if (error && (!*error || !(*error)[0]))
            *error = error_code ? error_code : "count_unavailable";
    }
}

static void flowd_status_count_add(struct json_object *resp, struct json_object *errors,
                                   int *all_ok, const char *field, const char *sql)
{
    int ok = 0;
    int count = flowd_count_sql_checked(sql, &ok);

    json_object_object_add(resp, field, json_object_new_int(count));
    if (!ok) {
        if (all_ok)
            *all_ok = 0;
        flowd_status_error_add(errors, field, "query_failed");
    }
}

static int flowd_compile_count_load(const char *field, const char *sql,
                                    struct json_object *blockers, struct json_object *warnings,
                                    int *ok)
{
    char msg[160];
    int count_ok = 0;
    int count = flowd_count_sql_checked(sql, &count_ok);

    if (!count_ok) {
        if (ok)
            *ok = 0;
        snprintf(msg, sizeof(msg), "compile_count_unavailable:%s", field ? field : "unknown");
        json_object_array_add(blockers, json_object_new_string(msg));
        snprintf(msg, sizeof(msg), "failed to read flowd compile input count: %s", field ? field : "unknown");
        json_object_array_add(warnings, json_object_new_string(msg));
    }
    return count;
}

static struct json_object *flowd_signature_datasets_load(void);

static void flowd_status_field_copy(struct json_object *dst, struct json_object *src,
                                    const char *field)
{
    struct json_object *value = NULL;

    if (dst && src && field && json_object_object_get_ex(src, field, &value) && value)
        json_object_object_add(dst, field, json_object_get(value));
}

static void flowd_status_configured_count_aliases(struct json_object *resp)
{
    static const char *const fields[] = {
        "enabled_sources",
        "enabled_country_policies",
        "enabled_objects",
        "enabled_custom_protocols",
        "enabled_route_groups",
        "enabled_wan_capacity",
        "enabled_wan_health",
        "enabled_split_rules",
        "enabled_domain_rules",
        "enabled_qos_classes",
        "enabled_qos_rules",
        "enabled_smart_qos_categories",
        "enabled_quota_rules",
        "enabled_conn_limit_rules",
        "enabled_app_rules",
    };
    struct json_object *semantics = json_object_new_object();
    size_t i;

    for (i = 0; i < sizeof(fields) / sizeof(fields[0]); i++) {
        struct json_object *value = NULL;
        char configured_field[96];

        if (!json_object_object_get_ex(resp, fields[i], &value) || !value)
            continue;
        snprintf(configured_field, sizeof(configured_field), "configured_%s",
                 fields[i]);
        json_object_object_add(resp, configured_field, json_object_get(value));
    }
    json_object_object_add(semantics, "configured_enabled_prefix",
                           json_object_new_string(
                               "configuration rows with enabled=1; not kernel-applied rules"));
    json_object_object_add(semantics, "legacy_enabled_prefix",
                           json_object_new_string(
                               "compatibility alias of configured_enabled_*"));
    json_object_object_add(semantics, "runtime_truth_field",
                           json_object_new_string("runtime_applied"));
    json_object_object_add(resp, "count_semantics", semantics);
}

static void flowd_status_metadata_load(struct json_object *errors, int *ok,
                                       char *last_error, size_t last_error_len,
                                       int64_t *updated_at)
{
    sqlite3_stmt *st;
    int rc;

    if (last_error && last_error_len)
        last_error[0] = '\0';
    if (updated_at)
        *updated_at = 0;
    st = flowd_config_prepare(
        "SELECT error,updated_at FROM ("
        "SELECT error,updated_at FROM flowd_apply_jobs WHERE error<>'' "
        "UNION ALL SELECT last_error,MAX(updated_at,last_import_at) "
        "FROM flowd_geoip_sources WHERE last_error<>'') "
        "ORDER BY updated_at DESC LIMIT 1");
    if (st) {
        rc = sqlite3_step(st);
        if (rc == SQLITE_ROW && last_error && last_error_len)
            snprintf(last_error, last_error_len, "%s", flowd_sqlite_text(st, 0, ""));
        else if (rc != SQLITE_DONE) {
            *ok = 0;
            flowd_status_error_add(errors, "last_error", "query_failed");
        }
        sqlite3_finalize(st);
    } else {
        *ok = 0;
        flowd_status_error_add(errors, "last_error", "query_failed");
    }
    st = flowd_config_prepare(
        "SELECT COALESCE(MAX(updated_at),0) FROM ("
        "SELECT updated_at FROM flowd_settings "
        "UNION ALL SELECT updated_at FROM flowd_geoip_sources "
        "UNION ALL SELECT updated_at FROM flowd_apply_jobs)");
    if (st) {
        rc = sqlite3_step(st);
        if (rc == SQLITE_ROW && updated_at)
            *updated_at = sqlite3_column_int64(st, 0);
        else {
            *ok = 0;
            flowd_status_error_add(errors, "updated_at", "query_failed");
        }
        sqlite3_finalize(st);
    } else {
        *ok = 0;
        flowd_status_error_add(errors, "updated_at", "query_failed");
    }
}

struct json_object *flowd_status_json(void)
{
    struct flowd_settings s;
    struct flowd_runtime_contract_input runtime_contract;
    struct json_object *resp = json_object_new_object();
    struct json_object *geoip = json_object_new_object();
    struct json_object *signature_datasets = NULL;
    struct json_object *errors = json_object_new_array();
    struct json_object *dependencies = json_object_new_object();
    struct json_object *datasets = json_object_new_object();
    char last_error[FLOWD_MAX_TEXT] = "";
    int64_t updated_at = 0;
    int ok = 1;
    int settings_available;
    int degraded;

    settings_available = flowd_settings_load(&s) == 0;
    if (!settings_available) {
        ok = 0;
        flowd_status_error_add(errors, "settings", "settings_unavailable");
    }
    json_object_object_add(resp, "ok", json_object_new_boolean(ok));
    json_object_object_add(resp, "service", json_object_new_string("dreamingwrt-flowd"));
    json_object_object_add(resp, "version", json_object_new_string(WORKER_STATUS_VERSION));
    json_object_object_add(resp, "schema_version", json_object_new_int(FLOWD_SCHEMA_VERSION));
    json_object_object_add(resp, "schema_source",
                           json_object_new_string("compiled:FLOWD_SCHEMA_VERSION"));
    json_object_object_add(resp, "migration_state", json_object_new_string("not_tracked"));
    json_object_object_add(resp, "settings_available",
                           json_object_new_boolean(settings_available));
    json_object_object_add(resp, "enabled", json_object_new_boolean(s.enabled));
    json_object_object_add(resp, "apply_mode", json_object_new_string(s.apply_mode));
    json_object_object_add(resp, "geoip_dir", json_object_new_string(s.geoip_dir));
    json_object_object_add(resp, "runtime_dir", json_object_new_string(s.runtime_dir));
    flowd_status_count_add(resp, errors, &ok, "sources", "SELECT COUNT(*) FROM flowd_geoip_sources");
    flowd_status_count_add(resp, errors, &ok, "enabled_sources", "SELECT COUNT(*) FROM flowd_geoip_sources WHERE enabled=1");
    flowd_status_count_add(resp, errors, &ok, "country_policies", "SELECT COUNT(*) FROM flowd_country_policies");
    flowd_status_count_add(resp, errors, &ok, "enabled_country_policies", "SELECT COUNT(*) FROM flowd_country_policies WHERE enabled=1");
    flowd_status_count_add(resp, errors, &ok, "objects", "SELECT COUNT(*) FROM flowd_objects");
    flowd_status_count_add(resp, errors, &ok, "enabled_objects", "SELECT COUNT(*) FROM flowd_objects WHERE enabled=1");
    flowd_status_count_add(resp, errors, &ok, "custom_protocols", "SELECT COUNT(*) FROM flowd_custom_protocols");
    flowd_status_count_add(resp, errors, &ok, "enabled_custom_protocols", "SELECT COUNT(*) FROM flowd_custom_protocols WHERE enabled=1");
    flowd_status_count_add(resp, errors, &ok, "route_groups", "SELECT COUNT(*) FROM flowd_route_groups");
    flowd_status_count_add(resp, errors, &ok, "enabled_route_groups", "SELECT COUNT(*) FROM flowd_route_groups WHERE enabled=1");
    flowd_status_count_add(resp, errors, &ok, "wan_capacity", "SELECT COUNT(*) FROM flowd_wan_capacity");
    flowd_status_count_add(resp, errors, &ok, "enabled_wan_capacity", "SELECT COUNT(*) FROM flowd_wan_capacity WHERE enabled=1");
    flowd_status_count_add(resp, errors, &ok, "wan_health", "SELECT COUNT(*) FROM flowd_wan_health");
    flowd_status_count_add(resp, errors, &ok, "enabled_wan_health", "SELECT COUNT(*) FROM flowd_wan_health WHERE enabled=1");
    flowd_status_count_add(resp, errors, &ok, "split_rules", "SELECT COUNT(*) FROM flowd_split_rules");
    flowd_status_count_add(resp, errors, &ok, "enabled_split_rules", "SELECT COUNT(*) FROM flowd_split_rules WHERE enabled=1");
    flowd_status_count_add(resp, errors, &ok, "domain_rules", "SELECT COUNT(*) FROM flowd_domain_rules");
    flowd_status_count_add(resp, errors, &ok, "enabled_domain_rules", "SELECT COUNT(*) FROM flowd_domain_rules WHERE enabled=1");
    flowd_status_count_add(resp, errors, &ok, "qos_classes", "SELECT COUNT(*) FROM flowd_qos_classes");
    flowd_status_count_add(resp, errors, &ok, "enabled_qos_classes", "SELECT COUNT(*) FROM flowd_qos_classes WHERE enabled=1");
    flowd_status_count_add(resp, errors, &ok, "qos_rules", "SELECT COUNT(*) FROM flowd_qos_rules");
    flowd_status_count_add(resp, errors, &ok, "enabled_qos_rules", "SELECT COUNT(*) FROM flowd_qos_rules WHERE enabled=1");
    flowd_status_count_add(resp, errors, &ok, "smart_qos_categories", "SELECT COUNT(*) FROM flowd_smart_qos_categories");
    flowd_status_count_add(resp, errors, &ok, "enabled_smart_qos_categories", "SELECT COUNT(*) FROM flowd_smart_qos_categories WHERE enabled=1");
    flowd_status_count_add(resp, errors, &ok, "quota_rules", "SELECT COUNT(*) FROM flowd_quota_rules");
    flowd_status_count_add(resp, errors, &ok, "enabled_quota_rules", "SELECT COUNT(*) FROM flowd_quota_rules WHERE enabled=1");
    flowd_status_count_add(resp, errors, &ok, "conn_limit_rules", "SELECT COUNT(*) FROM flowd_conn_limit_rules");
    flowd_status_count_add(resp, errors, &ok, "enabled_conn_limit_rules", "SELECT COUNT(*) FROM flowd_conn_limit_rules WHERE enabled=1");
    flowd_status_count_add(resp, errors, &ok, "app_rules", "SELECT COUNT(*) FROM flowd_app_rules");
    flowd_status_count_add(resp, errors, &ok, "enabled_app_rules", "SELECT COUNT(*) FROM flowd_app_rules WHERE enabled=1");
    flowd_status_count_add(resp, errors, &ok, "apply_jobs", "SELECT COUNT(*) FROM flowd_apply_jobs");
    flowd_status_configured_count_aliases(resp);
    json_object_object_add(geoip, "configured_mmdb_present", json_object_new_boolean(flowd_file_exists(FLOWD_DEFAULT_MMDB)));
    json_object_object_add(geoip, "configured_mmdb_valid", json_object_new_boolean(flowd_geoip_configured_mmdb_valid()));
    json_object_object_add(geoip, "auto_import_needed", json_object_new_boolean(flowd_geoip_auto_import_enabled()));
    json_object_object_add(geoip, "default_source", json_object_new_string(FLOWD_DEFAULT_GEOIP_SOURCE_ID));
    json_object_object_add(geoip, "unifi_style_system_mmdb_present", json_object_new_boolean(flowd_file_exists("/usr/share/dpi/geoip/GeoLite2-Country.mmdb")));
    json_object_object_add(geoip, "xt_geoip_dir_present", json_object_new_boolean(flowd_dir_exists("/usr/share/xt_geoip")));
    json_object_object_add(geoip, "geoip_dir_present", json_object_new_boolean(flowd_dir_exists(s.geoip_dir)));
    json_object_object_add(geoip, "runtime_dir_present", json_object_new_boolean(flowd_dir_exists(s.runtime_dir)));
    json_object_object_add(resp, "geoip", geoip);
    signature_datasets = flowd_signature_datasets_load();
    json_object_object_add(resp, "signature_datasets", signature_datasets);
    flowd_status_metadata_load(errors, &ok, last_error, sizeof(last_error), &updated_at);
    json_object_object_add(dependencies, "config_db",
                           json_object_new_boolean(g_flowd_config_db != NULL));
    json_object_object_add(dependencies, "geoip_mmdb",
                           json_object_new_boolean(flowd_geoip_configured_mmdb_valid()));
    json_object_object_add(resp, "dependencies", dependencies);
    flowd_status_field_copy(datasets, resp, "sources");
    flowd_status_field_copy(datasets, resp, "country_policies");
    flowd_status_field_copy(datasets, resp, "objects");
    flowd_status_field_copy(datasets, resp, "custom_protocols");
    flowd_status_field_copy(datasets, resp, "route_groups");
    flowd_status_field_copy(datasets, resp, "split_rules");
    flowd_status_field_copy(datasets, resp, "domain_rules");
    flowd_status_field_copy(datasets, resp, "qos_rules");
    flowd_status_field_copy(datasets, resp, "quota_rules");
    flowd_status_field_copy(datasets, resp, "conn_limit_rules");
    flowd_status_field_copy(datasets, resp, "app_rules");
    flowd_status_field_copy(datasets, resp, "apply_jobs");
    json_object_object_add(resp, "datasets", datasets);
    if (!ok && !last_error[0])
        snprintf(last_error, sizeof(last_error), "%s", "status_query_failed");
    degraded = !ok || last_error[0] != '\0';
    json_object_object_add(resp, "state", json_object_new_string(
        degraded ? "degraded" : (s.enabled ? "running" : "disabled")));
    json_object_object_add(resp, "degraded", json_object_new_boolean(degraded));
    json_object_object_add(resp, "last_error", json_object_new_string(last_error));
    json_object_object_add(resp, "updated_at", json_object_new_int64(updated_at));
    if (json_object_array_length(errors) > 0)
        json_object_object_add(resp, "errors", errors);
    else
        json_object_put(errors);
    flowd_response_set_ok(resp, ok);
    runtime_contract.configured_enabled = s.enabled;
    runtime_contract.configured_apply_mode = s.apply_mode;
    runtime_contract.config_store_available = settings_available;
    runtime_contract.runtime_snapshot_available = flowd_file_exists(FLOWD_DEFAULT_FLOW_DB_PATH);
    runtime_contract.nft_binary_available = access(FLOWD_NFT_BINARY, X_OK) == 0;
    runtime_contract.runtime_dir_available = flowd_dir_exists(s.runtime_dir);
    flowd_runtime_contract_add(resp, &runtime_contract);
    json_object_object_add(resp, "state", json_object_new_string(
        !ok ? "degraded" : (s.enabled ? "running-plan-only" : "disabled")));
    json_object_object_add(resp, "ts", json_object_new_int64(flowd_now_s()));
    return resp;
}

struct json_object *flowd_settings_json(void)
{
    struct flowd_settings s;
    struct flowd_runtime_contract_input runtime_contract;
    struct json_object *resp = json_object_new_object();
    int ok;

    ok = flowd_settings_load(&s) == 0;
    json_object_object_add(resp, "ok", json_object_new_boolean(ok));
    json_object_object_add(resp, "settings_available", json_object_new_boolean(ok));
    json_object_object_add(resp, "enabled", json_object_new_boolean(s.enabled));
    json_object_object_add(resp, "geoip_dir", json_object_new_string(s.geoip_dir));
    json_object_object_add(resp, "runtime_dir", json_object_new_string(s.runtime_dir));
    json_object_object_add(resp, "apply_mode", json_object_new_string(s.apply_mode));
    if (!ok)
        json_object_object_add(resp, "error", json_object_new_string("settings_unavailable"));
    runtime_contract.configured_enabled = s.enabled;
    runtime_contract.configured_apply_mode = s.apply_mode;
    runtime_contract.config_store_available = ok;
    runtime_contract.runtime_snapshot_available = flowd_file_exists(FLOWD_DEFAULT_FLOW_DB_PATH);
    runtime_contract.nft_binary_available = access(FLOWD_NFT_BINARY, X_OK) == 0;
    runtime_contract.runtime_dir_available = flowd_dir_exists(s.runtime_dir);
    flowd_runtime_contract_add(resp, &runtime_contract);
    return resp;
}

struct json_object *flowd_settings_update(struct json_object *body)
{
    struct flowd_settings s;
    sqlite3_stmt *st;
    const char *geoip_dir;
    const char *runtime_dir;
    const char *apply_mode;
    int ok = 0;
    struct json_object *resp;

    if (flowd_settings_load(&s) != 0)
        return flowd_error("settings_unavailable", "flowd settings are unavailable");
    if (!body || !json_object_is_type(body, json_type_object))
        body = NULL;
    s.enabled = flowd_json_bool(body, "enabled", s.enabled);
    geoip_dir = flowd_json_str(body, "geoip_dir", s.geoip_dir);
    runtime_dir = flowd_json_str(body, "runtime_dir", s.runtime_dir);
    apply_mode = flowd_json_str(body, "apply_mode", s.apply_mode);
    if (!geoip_dir || !geoip_dir[0] || !runtime_dir || !runtime_dir[0] ||
        !flowd_path_ok(geoip_dir) || !flowd_path_ok(runtime_dir) ||
        !(apply_mode && !strcmp(apply_mode, FLOWD_EFFECTIVE_APPLY_MODE)))
        return flowd_error("invalid_settings", "invalid flowd settings");
    snprintf(s.geoip_dir, sizeof(s.geoip_dir), "%s", geoip_dir);
    snprintf(s.runtime_dir, sizeof(s.runtime_dir), "%s", runtime_dir);
    snprintf(s.apply_mode, sizeof(s.apply_mode), "%s", apply_mode);
    st = flowd_config_prepare(
        "UPDATE flowd_settings SET enabled=?1,geoip_dir=?2,runtime_dir=?3,apply_mode=?4,updated_at=?5 WHERE id=1");
    if (st) {
        sqlite3_bind_int(st, 1, s.enabled);
        sqlite3_bind_text(st, 2, s.geoip_dir, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 3, s.runtime_dir, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 4, s.apply_mode, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 5, flowd_now_s());
        ok = sqlite3_step(st) == SQLITE_DONE && sqlite3_changes(g_flowd_config_db) > 0;
        sqlite3_finalize(st);
    }
    resp = flowd_settings_json();
    flowd_response_set_ok(resp, ok);
    json_object_object_add(resp, "saved", json_object_new_boolean(ok));
    if (!ok)
        json_object_object_add(resp, "error", json_object_new_string("save_failed"));
    return resp;
}

static void flowd_source_row_json(struct json_object *arr, sqlite3_stmt *st)
{
    const char *meta_s = (const char *)sqlite3_column_text(st, 8);
    const char *path = (const char *)sqlite3_column_text(st, 3);
    struct json_object *o = json_object_new_object();

    json_object_object_add(o, "id", flowd_sqlite_text_json(st, 0));
    json_object_object_add(o, "name", flowd_sqlite_text_json(st, 1));
    json_object_object_add(o, "type", flowd_sqlite_text_json(st, 2));
    json_object_object_add(o, "path", json_object_new_string(path ? path : ""));
    json_object_object_add(o, "edition", flowd_sqlite_text_json(st, 4));
    json_object_object_add(o, "enabled", json_object_new_boolean(sqlite3_column_int(st, 5)));
    json_object_object_add(o, "auto_update", json_object_new_boolean(sqlite3_column_int(st, 6)));
    json_object_object_add(o, "license_ref", flowd_sqlite_text_json(st, 7));
    json_object_object_add(o, "meta", flowd_json_parse_or_object(meta_s));
    json_object_object_add(o, "path_present", json_object_new_boolean(path && (flowd_file_exists(path) || flowd_dir_exists(path))));
    json_object_object_add(o, "updated_at", json_object_new_int64(sqlite3_column_int64(st, 9)));
    json_object_object_add(o, "last_import_at", json_object_new_int64(sqlite3_column_int64(st, 10)));
    json_object_object_add(o, "last_import_status", flowd_sqlite_text_json(st, 11));
    json_object_object_add(o, "last_error", flowd_sqlite_text_json(st, 12));
    json_object_array_add(arr, o);
}

struct json_object *flowd_geoip_sources_json(void)
{
    sqlite3_stmt *st;
    struct json_object *resp = json_object_new_object();
    struct json_object *arr = json_object_new_array();
    int ok = 0;
    int rc;

    st = flowd_config_prepare(
        "SELECT id,name,type,path,edition,enabled,auto_update,license_ref,meta_json,updated_at,"
        "last_import_at,last_import_status,last_error FROM flowd_geoip_sources ORDER BY id");
    if (st) {
        while ((rc = sqlite3_step(st)) == SQLITE_ROW)
            flowd_source_row_json(arr, st);
        ok = rc == SQLITE_DONE;
        if (!ok)
            fprintf(stderr, "[dreamingwrt-flowd] geoip sources query failed: %s\n",
                    g_flowd_config_db ? sqlite3_errmsg(g_flowd_config_db) : "database unavailable");
        sqlite3_finalize(st);
    }
    json_object_object_add(resp, "ok", json_object_new_boolean(ok));
    json_object_object_add(resp, "sources", arr);
    if (!ok)
        json_object_object_add(resp, "error", json_object_new_string("geoip_sources_unavailable"));
    return resp;
}

static int flowd_geoip_source_load_existing(const char *id,
                                            char *name, size_t name_len,
                                            char *type, size_t type_len,
                                            char *path, size_t path_len,
                                            char *edition, size_t edition_len,
                                            int *enabled, int *auto_update,
                                            char *license_ref, size_t license_ref_len,
                                            char *meta_json, size_t meta_json_len)
{
    sqlite3_stmt *st;
    int rc;

    if (!flowd_id_ok(id))
        return -1;
    st = flowd_config_prepare(
        "SELECT name,type,path,edition,enabled,auto_update,license_ref,meta_json "
        "FROM flowd_geoip_sources WHERE id=?1");
    if (!st)
        return -1;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) {
        snprintf(name, name_len, "%s",
                 sqlite3_column_text(st, 0) ? (const char *)sqlite3_column_text(st, 0) : "");
        snprintf(type, type_len, "%s",
                 sqlite3_column_text(st, 1) ? (const char *)sqlite3_column_text(st, 1) : "maxmind-mmdb");
        snprintf(path, path_len, "%s",
                 sqlite3_column_text(st, 2) ? (const char *)sqlite3_column_text(st, 2) : "");
        snprintf(edition, edition_len, "%s",
                 sqlite3_column_text(st, 3) ? (const char *)sqlite3_column_text(st, 3) : "");
        if (enabled)
            *enabled = sqlite3_column_int(st, 4) ? 1 : 0;
        if (auto_update)
            *auto_update = sqlite3_column_int(st, 5) ? 1 : 0;
        snprintf(license_ref, license_ref_len, "%s",
                 sqlite3_column_text(st, 6) ? (const char *)sqlite3_column_text(st, 6) : "");
        snprintf(meta_json, meta_json_len, "%s",
                 sqlite3_column_text(st, 7) ? (const char *)sqlite3_column_text(st, 7) : "{}");
        sqlite3_finalize(st);
        return 1;
    }
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

static int flowd_geoip_source_save_one(struct json_object *src)
{
    sqlite3_stmt *st;
    struct json_object *meta = NULL;
    char name_buf[129] = "";
    char type_buf[33] = "maxmind-mmdb";
    char path_buf[512] = "";
    char edition_buf[65] = "";
    char license_ref_buf[129] = "";
    char meta_json_buf[FLOWD_MAX_JSON + 1] = "{}";
    const char *id, *name, *type, *path, *edition, *license_ref;
    const char *meta_s = meta_json_buf;
    int enabled, auto_update, ok = 0;
    int64_t now = flowd_now_s();

    if (!src || !json_object_is_type(src, json_type_object))
        return -1;
    enabled = 1;
    auto_update = 0;
    id = flowd_json_str(src, "id", "");
    if (id[0]) {
        int existing;

        existing = flowd_geoip_source_load_existing(id, name_buf, sizeof(name_buf),
                                                    type_buf, sizeof(type_buf),
                                                    path_buf, sizeof(path_buf),
                                                    edition_buf, sizeof(edition_buf),
                                                    &enabled, &auto_update,
                                                    license_ref_buf, sizeof(license_ref_buf),
                                                    meta_json_buf, sizeof(meta_json_buf));
        if (existing < 0)
            return -1;
    }
    name = flowd_json_str(src, "name", name_buf);
    type = flowd_json_str(src, "type", type_buf);
    path = flowd_json_str(src, "path", path_buf);
    edition = flowd_json_str(src, "edition", edition_buf);
    license_ref = flowd_json_str(src, "license_ref", license_ref_buf);
    enabled = flowd_json_bool(src, "enabled", enabled);
    auto_update = flowd_json_bool(src, "auto_update", auto_update);
    if (!flowd_id_ok(id) || !flowd_text_ok(name, 128) || !flowd_path_ok(path) ||
        !flowd_token_ok(type, 32) || !flowd_text_ok(edition, 64) ||
        (license_ref[0] && !flowd_token_ok(license_ref, 128)))
        return -1;
    if (strcmp(type, "maxmind-mmdb") && strcmp(type, "geolite2-mmdb") &&
        strcmp(type, "github-mmdb") &&
        strcmp(type, "xt_geoip") && strcmp(type, "cidr-dir") &&
        strcmp(type, "static-cidr") && strcmp(type, "custom"))
        return -1;
    if (json_object_object_get_ex(src, "meta", &meta) && meta) {
        if (!flowd_json_fits(meta, FLOWD_MAX_JSON))
            return -1;
        meta_s = json_object_to_json_string_ext(meta, JSON_C_TO_STRING_PLAIN);
    }
    st = flowd_config_prepare(
        "INSERT INTO flowd_geoip_sources"
        "(id,name,type,path,edition,enabled,auto_update,license_ref,meta_json,created_at,updated_at) "
        "VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?10) "
        "ON CONFLICT(id) DO UPDATE SET name=excluded.name,type=excluded.type,path=excluded.path,"
        "edition=excluded.edition,enabled=excluded.enabled,auto_update=excluded.auto_update,"
        "license_ref=excluded.license_ref,meta_json=excluded.meta_json,updated_at=excluded.updated_at");
    if (st) {
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, name, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 3, type, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 4, path, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 5, edition, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 6, enabled ? 1 : 0);
        sqlite3_bind_int(st, 7, auto_update ? 1 : 0);
        sqlite3_bind_text(st, 8, license_ref, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 9, meta_s, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 10, now);
        ok = sqlite3_step(st) == SQLITE_DONE;
        sqlite3_finalize(st);
    }
    return ok ? 0 : -1;
}

struct json_object *flowd_geoip_source_update(struct json_object *body)
{
    struct json_object *arr = NULL;
    int ok = 1, saved = 0, i, n;
    struct json_object *resp;

    if (!body || !json_object_is_type(body, json_type_object))
        return flowd_error("invalid_request", "geoip source body must be an object");
    if (json_object_object_get_ex(body, "sources", &arr) && arr &&
        json_object_is_type(arr, json_type_array)) {
        n = json_object_array_length(arr);
        for (i = 0; i < n; i++) {
            if (flowd_geoip_source_save_one(json_object_array_get_idx(arr, i)) == 0)
                saved++;
            else
                ok = 0;
        }
    } else {
        ok = flowd_geoip_source_save_one(body) == 0;
        saved = ok ? 1 : 0;
    }
    resp = flowd_geoip_sources_json();
    flowd_response_set_ok(resp, ok);
    json_object_object_add(resp, "saved", json_object_new_int(saved));
    if (!ok)
        json_object_object_add(resp, "error", json_object_new_string("partial_or_failed_save"));
    return resp;
}

struct json_object *flowd_geoip_source_delete(struct json_object *body)
{
    sqlite3_stmt *st;
    const char *id = flowd_json_str(body, "id", "");
    int ok = 0;
    struct json_object *resp;

    if (!flowd_id_ok(id))
        return flowd_error("invalid_id", "invalid geoip source id");
    st = flowd_config_prepare("DELETE FROM flowd_geoip_sources WHERE id=?1");
    if (st) {
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        ok = sqlite3_step(st) == SQLITE_DONE && sqlite3_changes(g_flowd_config_db) > 0;
        sqlite3_finalize(st);
    }
    resp = flowd_geoip_sources_json();
    flowd_response_set_ok(resp, ok);
    json_object_object_add(resp, "deleted", json_object_new_boolean(ok));
    if (!ok)
        json_object_object_add(resp, "error", json_object_new_string("not_found"));
    return resp;
}

struct json_object *flowd_geoip_import_status(struct json_object *body)
{
    struct json_object *resp = flowd_geoip_sources_json();
    struct json_object *fs = json_object_new_object();
    (void)body;

    json_object_object_add(fs, "configured_mmdb", json_object_new_boolean(flowd_file_exists(FLOWD_DEFAULT_MMDB)));
    json_object_object_add(fs, "configured_mmdb_valid", json_object_new_boolean(flowd_geoip_configured_mmdb_valid()));
    json_object_object_add(fs, "configured_mmdb_path", json_object_new_string(FLOWD_DEFAULT_MMDB));
    json_object_object_add(fs, "auto_import_needed", json_object_new_boolean(flowd_geoip_auto_import_enabled()));
    json_object_object_add(fs, "system_mmdb", json_object_new_boolean(flowd_file_exists("/usr/share/dpi/geoip/GeoLite2-Country.mmdb")));
    json_object_object_add(fs, "xt_geoip_le", json_object_new_boolean(flowd_dir_exists("/usr/share/xt_geoip/LE")));
    json_object_object_add(fs, "xt_geoip_be", json_object_new_boolean(flowd_dir_exists("/usr/share/xt_geoip/BE")));
    json_object_object_add(resp, "filesystem", fs);
    return resp;
}

static int flowd_file_size_ok(const char *path, off_t *out)
{
    struct stat st;

    if (!path || stat(path, &st) != 0 || !S_ISREG(st.st_mode))
        return -1;
    if (st.st_size <= 0 || st.st_size > (off_t)FLOWD_MAX_IMPORT_BYTES)
        return -1;
    if (out)
        *out = st.st_size;
    return 0;
}

static int flowd_mmdb_validate(const char *path, char *err, size_t err_len)
{
    static const unsigned char marker[] = {
        0xab, 0xcd, 0xef, 'M', 'a', 'x', 'M', 'i', 'n', 'd', '.', 'c', 'o', 'm'
    };
    unsigned char buf[131072];
    FILE *fp;
    off_t size;
    size_t n, i;

    if (flowd_file_size_ok(path, &size) != 0) {
        snprintf(err, err_len, "invalid_size");
        return -1;
    }
    fp = fopen(path, "rb");
    if (!fp) {
        snprintf(err, err_len, "open_failed");
        return -1;
    }
    if (size > (off_t)sizeof(buf) && fseeko(fp, size - (off_t)sizeof(buf), SEEK_SET) != 0) {
        fclose(fp);
        snprintf(err, err_len, "seek_failed");
        return -1;
    }
    n = fread(buf, 1, sizeof(buf), fp);
    fclose(fp);
    if (n < sizeof(marker)) {
        snprintf(err, err_len, "too_small");
        return -1;
    }
    for (i = 0; i + sizeof(marker) <= n; i++) {
        if (memcmp(buf + i, marker, sizeof(marker)) == 0)
            return 0;
    }
    snprintf(err, err_len, "not_maxmind_mmdb");
    return -1;
}

int flowd_geoip_configured_mmdb_valid(void)
{
    char err[64] = "";

    return flowd_mmdb_validate(FLOWD_DEFAULT_MMDB, err, sizeof(err)) == 0;
}

static int flowd_target_tmp(const char *dst, char *tmp, size_t tmp_len, char *err, size_t err_len)
{
    char dir[FLOWD_MAX_TEXT];
    char *slash;

    if (!flowd_path_ok(dst)) {
        snprintf(err, err_len, "invalid_target_path");
        return -1;
    }
    snprintf(dir, sizeof(dir), "%s", dst);
    slash = strrchr(dir, '/');
    if (!slash || slash == dir) {
        snprintf(err, err_len, "invalid_target_dir");
        return -1;
    }
    *slash = '\0';
    if (flowd_mkdir_p(dir, 0755) != 0) {
        snprintf(err, err_len, "mkdir_failed");
        return -1;
    }
    snprintf(tmp, tmp_len, "%s.tmp.%u", dst, (unsigned)getpid());
    return 0;
}

static int flowd_copy_file_atomic(const char *src, const char *dst, char *err, size_t err_len)
{
    char tmp[FLOWD_MAX_TEXT + 64];
    unsigned char buf[32768];
    int in = -1, out = -1;
    ssize_t n;
    int rc = -1;

    if (!flowd_path_ok(src)) {
        snprintf(err, err_len, "invalid_source_path");
        return -1;
    }
    if (flowd_target_tmp(dst, tmp, sizeof(tmp), err, err_len) != 0)
        return -1;
    if (flowd_mmdb_validate(src, err, err_len) != 0)
        return -1;
    in = open(src, O_RDONLY);
    if (in < 0) {
        snprintf(err, err_len, "open_source_failed");
        goto done;
    }
    out = open(tmp, O_CREAT | O_TRUNC | O_WRONLY, 0644);
    if (out < 0) {
        snprintf(err, err_len, "open_target_failed");
        goto done;
    }
    while ((n = read(in, buf, sizeof(buf))) > 0) {
        unsigned char *p = buf;
        ssize_t left = n;

        while (left > 0) {
            ssize_t w = write(out, p, left);
            if (w <= 0) {
                snprintf(err, err_len, "write_failed");
                goto done;
            }
            p += w;
            left -= w;
        }
    }
    if (n < 0) {
        snprintf(err, err_len, "read_failed");
        goto done;
    }
    if (fsync(out) != 0) {
        snprintf(err, err_len, "fsync_failed");
        goto done;
    }
    if (close(out) != 0) {
        out = -1;
        snprintf(err, err_len, "close_target_failed");
        goto done;
    }
    out = -1;
    if (flowd_mmdb_validate(tmp, err, err_len) != 0)
        goto done;
    if (rename(tmp, dst) != 0) {
        snprintf(err, err_len, "rename_failed");
        goto done;
    }
    rc = 0;
done:
    if (in >= 0)
        close(in);
    if (out >= 0)
        close(out);
    if (rc != 0)
        unlink(tmp);
    return rc;
}

struct flowd_download_state {
    FILE *fp;
    size_t written;
};

static size_t flowd_curl_write(void *ptr, size_t size, size_t nmemb, void *stream)
{
    struct flowd_download_state *st = stream;
    size_t n;

    if (!st || !st->fp)
        return 0;
    if (size != 0 && nmemb > FLOWD_MAX_IMPORT_BYTES / size)
        return 0;
    n = size * nmemb;
    if (st->written > FLOWD_MAX_IMPORT_BYTES || n > FLOWD_MAX_IMPORT_BYTES - st->written)
        return 0;
    if (fwrite(ptr, 1, n, st->fp) != n)
        return 0;
    st->written += n;
    return n;
}

static int flowd_download_mmdb_atomic(const char *url, const char *dst, char *err, size_t err_len)
{
    struct flowd_download_state st;
    char tmp[FLOWD_MAX_TEXT + 64];
    CURL *curl;
    CURLcode cc;
    long http_code = 0;
    int rc = -1;

    if (!flowd_url_ok(url) || flowd_target_tmp(dst, tmp, sizeof(tmp), err, err_len) != 0)
        return -1;
    st.fp = fopen(tmp, "wb");
    st.written = 0;
    if (!st.fp) {
        snprintf(err, err_len, "download_open_failed");
        return -1;
    }
    curl = curl_easy_init();
    if (!curl) {
        snprintf(err, err_len, "curl_init_failed");
        goto done;
    }
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, "https");
    curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS_STR, "https");
    curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 20L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 300L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "dreamingwrt-flowd/1.0");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, flowd_curl_write);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &st);
    cc = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    curl_easy_cleanup(curl);
    if (cc != CURLE_OK) {
        snprintf(err, err_len, "download_failed:http_%ld:%s", http_code, curl_easy_strerror(cc));
        goto done;
    }
    if (fflush(st.fp) != 0 || fsync(fileno(st.fp)) != 0) {
        snprintf(err, err_len, "download_fsync_failed");
        goto done;
    }
    if (fclose(st.fp) != 0) {
        st.fp = NULL;
        snprintf(err, err_len, "download_close_failed");
        goto done_closed;
    }
    st.fp = NULL;
    if (flowd_mmdb_validate(tmp, err, err_len) != 0)
        goto done_closed;
    if (rename(tmp, dst) != 0) {
        snprintf(err, err_len, "rename_failed");
        goto done_closed;
    }
    rc = 0;
done:
    if (st.fp)
        fclose(st.fp);
done_closed:
    if (rc != 0)
        unlink(tmp);
    return rc;
}

static int flowd_source_lookup(const char *id, char *path, size_t path_len,
                              char *url, size_t url_len, char *edition, size_t edition_len)
{
    sqlite3_stmt *st;
    int found = 0;

    snprintf(path, path_len, "%s", FLOWD_DEFAULT_MMDB);
    snprintf(url, url_len, "%s", FLOWD_P3TERX_COUNTRY_URL);
    snprintf(edition, edition_len, "%s", "GeoLite2-Country");
    st = flowd_config_prepare("SELECT path,edition,meta_json FROM flowd_geoip_sources WHERE id=?1");
    if (st) {
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) == SQLITE_ROW) {
            const char *p = (const char *)sqlite3_column_text(st, 0);
            const char *e = (const char *)sqlite3_column_text(st, 1);
            const char *meta_s = (const char *)sqlite3_column_text(st, 2);
            struct json_object *meta = flowd_json_parse_or_object(meta_s);
            const char *u = flowd_json_str(meta, "url", url);

            found = 1;
            if (flowd_path_ok(p))
                snprintf(path, path_len, "%s", p);
            if (e && e[0] && flowd_token_ok(e, 64))
                snprintf(edition, edition_len, "%s", e);
            if (flowd_url_ok(u))
                snprintf(url, url_len, "%s", u);
            json_object_put(meta);
        }
        sqlite3_finalize(st);
    }
    return found ? 0 : -1;
}

static int flowd_source_note_import(const char *id, const char *path, const char *edition,
                                    const char *status, const char *error)
{
    sqlite3_stmt *st;
    int ok = 0;

    if (!flowd_id_ok(id))
        return -1;
    st = flowd_config_prepare(
        "UPDATE flowd_geoip_sources SET path=?2,edition=?3,updated_at=?4,"
        "last_import_at=?4,last_import_status=?5,last_error=?6 WHERE id=?1");
    if (st) {
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, path ? path : FLOWD_DEFAULT_MMDB, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 3, edition ? edition : "GeoLite2-Country", -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 4, flowd_now_s());
        sqlite3_bind_text(st, 5, status ? status : "unknown", -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 6, error ? error : "", -1, SQLITE_TRANSIENT);
        ok = sqlite3_step(st) == SQLITE_DONE && sqlite3_changes(g_flowd_config_db) > 0;
        sqlite3_finalize(st);
    }
    return ok ? 0 : -1;
}

struct json_object *flowd_geoip_import(struct json_object *body)
{
    const char *id = flowd_json_str(body, "id", FLOWD_DEFAULT_GEOIP_SOURCE_ID);
    const char *path = flowd_json_str(body, "path", "");
    const char *body_url = flowd_json_str(body, "url", "");
    const char *target_override = flowd_json_str(body, "target_path", "");
    char target[FLOWD_MAX_TEXT];
    char url[1024];
    char edition[64];
    char err[256] = "";
    int ok;
    struct json_object *resp;

    if (!flowd_id_ok(id))
        return flowd_error("invalid_import_status", "invalid geoip import status");
    if (flowd_source_lookup(id, target, sizeof(target), url, sizeof(url), edition, sizeof(edition)) != 0)
        return flowd_error("source_not_found", "geoip source not found");
    if (target_override && target_override[0] && !flowd_path_ok(target_override))
        return flowd_error("invalid_target_path", "invalid geoip target path");
    if (body_url && body_url[0] && !flowd_url_ok(body_url))
        return flowd_error("invalid_source_url", "invalid geoip source url");
    if (path && path[0] && !flowd_path_ok(path))
        return flowd_error("invalid_source_path", "invalid geoip source path");
    if (target_override && target_override[0])
        snprintf(target, sizeof(target), "%s", target_override);
    if (body_url && body_url[0])
        snprintf(url, sizeof(url), "%s", body_url);

    if (path && path[0]) {
        ok = flowd_copy_file_atomic(path, target, err, sizeof(err)) == 0;
    } else {
        ok = flowd_download_mmdb_atomic(url, target, err, sizeof(err)) == 0;
    }
    flowd_source_note_import(id, target, edition, ok ? "installed" : "failed", ok ? "" : err);
    resp = flowd_geoip_import_status(body);
    flowd_response_set_ok(resp, ok);
    json_object_object_add(resp, "installed", json_object_new_boolean(ok));
    json_object_object_add(resp, "target_path", json_object_new_string(target));
    json_object_object_add(resp, "source_url", json_object_new_string(url));
    if (!ok) {
        json_object_object_add(resp, "error", json_object_new_string(err[0] ? err : "import_failed"));
        json_object_object_add(resp, "message", json_object_new_string("GeoIP database import failed"));
    }
    return resp;
}

int flowd_geoip_auto_import_enabled(void)
{
    sqlite3_stmt *st;
    int enabled = 0;

    if (flowd_geoip_configured_mmdb_valid())
        return 0;
    st = flowd_config_prepare(
        "SELECT enabled,auto_update FROM flowd_geoip_sources WHERE id=?1");
    if (!st)
        return 0;
    sqlite3_bind_text(st, 1, FLOWD_DEFAULT_GEOIP_SOURCE_ID, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW)
        enabled = sqlite3_column_int(st, 0) && sqlite3_column_int(st, 1);
    sqlite3_finalize(st);
    return enabled ? 1 : 0;
}

int flowd_geoip_auto_import_once(void)
{
    struct json_object *body;
    struct json_object *resp;
    struct json_object *installed = NULL;
    int ok = 0;

    if (!flowd_geoip_auto_import_enabled())
        return 0;
    body = json_object_new_object();
    if (!body)
        return -1;
    json_object_object_add(body, "id", json_object_new_string(FLOWD_DEFAULT_GEOIP_SOURCE_ID));
    resp = flowd_geoip_import(body);
    if (resp && json_object_object_get_ex(resp, "installed", &installed))
        ok = json_object_get_boolean(installed) ? 1 : 0;
    if (resp)
        json_object_put(resp);
    json_object_put(body);
    return ok ? 0 : -1;
}

static void flowd_policy_row_json(struct json_object *arr, sqlite3_stmt *st)
{
    const char *countries_s = (const char *)sqlite3_column_text(st, 5);
    struct json_object *o = json_object_new_object();

    json_object_object_add(o, "id", flowd_sqlite_text_json(st, 0));
    json_object_object_add(o, "name", flowd_sqlite_text_json(st, 1));
    json_object_object_add(o, "enabled", json_object_new_boolean(sqlite3_column_int(st, 2)));
    json_object_object_add(o, "priority", json_object_new_int(sqlite3_column_int(st, 3)));
    json_object_object_add(o, "direction", flowd_sqlite_text_json(st, 4));
    json_object_object_add(o, "countries", flowd_json_parse_or_array(countries_s));
    json_object_object_add(o, "action", flowd_sqlite_text_json(st, 6));
    json_object_object_add(o, "target", flowd_sqlite_text_json(st, 7));
    json_object_object_add(o, "family", flowd_sqlite_text_json(st, 8));
    json_object_object_add(o, "remark", flowd_sqlite_text_json(st, 9));
    json_object_object_add(o, "updated_at", json_object_new_int64(sqlite3_column_int64(st, 10)));
    json_object_array_add(arr, o);
}

static int flowd_signature_db_path(char *path, size_t path_len,
                                   enum jmx_system_db_source *source,
                                   char *error, size_t error_len)
{
    enum jmx_system_db_source resolved_source = JMX_SYSTEM_DB_SOURCE_NONE;

    if (jmx_system_db_resolve(JMX_SYSTEM_DB_SIGNATURE, path, path_len,
                              &resolved_source, error, error_len) == 0) {
        if (source)
            *source = resolved_source;
        return 0;
    }
    if (source)
        *source = JMX_SYSTEM_DB_SOURCE_NONE;
    fprintf(stderr, "[dreamingwrt-flowd] signature DB resolve failed: %s\n",
            error && error[0] ? error : "unknown_error");
    return -1;
}

static void flowd_json_set_int64(struct json_object *o, const char *key, int64_t value)
{
    if (!o || !key)
        return;
    json_object_object_del(o, key);
    json_object_object_add(o, key, json_object_new_int64(value));
}

static int64_t flowd_json_int64_member(struct json_object *o, const char *key)
{
    struct json_object *v = NULL;

    if (!o || !key || !json_object_object_get_ex(o, key, &v) || !v)
        return 0;
    return json_object_get_int64(v);
}

static int64_t flowd_json_int64_child_member(struct json_object *o, const char *child,
                                             const char *key)
{
    struct json_object *v = NULL;

    if (!o || !child || !json_object_object_get_ex(o, child, &v) || !v)
        return 0;
    return flowd_json_int64_member(v, key);
}

static int flowd_plan_count_i64(int64_t value)
{
    if (value <= 0)
        return 0;
    if (value > 2147483647LL)
        return 2147483647;
    return (int)value;
}

static int flowd_signature_table_exists(sqlite3 *db, const char *name)
{
    sqlite3_stmt *st = NULL;
    int exists = 0;

    if (!db || !flowd_token_ok(name, 64))
        return 0;
    if (sqlite3_prepare_v2(db,
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1 LIMIT 1",
        -1, &st, NULL) != SQLITE_OK)
        return 0;
    sqlite3_bind_text(st, 1, name, -1, SQLITE_TRANSIENT);
    exists = sqlite3_step(st) == SQLITE_ROW;
    sqlite3_finalize(st);
    return exists ? 1 : 0;
}

static int64_t flowd_signature_scalar_i64(sqlite3 *db, const char *sql, int *ok)
{
    sqlite3_stmt *st = NULL;
    int64_t value = 0;
    int rc;

    if (ok)
        *ok = 0;
    if (!db || !sql)
        return 0;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return 0;
    rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) {
        value = sqlite3_column_int64(st, 0);
        if (ok)
            *ok = 1;
    }
    sqlite3_finalize(st);
    return value;
}

static void flowd_signature_count_add(sqlite3 *db, struct json_object *o,
                                      const char *field, const char *sql)
{
    int ok = 0;
    int64_t value = flowd_signature_scalar_i64(db, sql, &ok);

    if (!o || !field)
        return;
    json_object_object_add(o, field, json_object_new_int64(ok ? value : 0));
}

static void flowd_signature_table_state_add(sqlite3 *db, struct json_object *o,
                                            const char *field, const char *table)
{
    int present = flowd_signature_table_exists(db, table);

    if (!o || !field || !table)
        return;
    json_object_object_add(o, field, json_object_new_boolean(present));
}

static void flowd_signature_group_counts_add(sqlite3 *db, struct json_object *parent,
                                             const char *field, const char *sql,
                                             const char *key_name,
                                             const char *label_name)
{
    sqlite3_stmt *st = NULL;
    struct json_object *arr;
    int rc;

    if (!parent || !field)
        return;
    arr = json_object_new_array();
    if (!db || !sql || sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) {
        json_object_object_add(parent, field, arr);
        return;
    }
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        const char *key = (const char *)sqlite3_column_text(st, 0);
        const char *label = label_name ? (const char *)sqlite3_column_text(st, 1) : NULL;
        int count_col = label_name ? 2 : 1;
        struct json_object *o = json_object_new_object();

        json_object_object_add(o, key_name ? key_name : "key",
                               json_object_new_string(key ? key : ""));
        if (label_name)
            json_object_object_add(o, label_name, json_object_new_string(label ? label : ""));
        json_object_object_add(o, "enabled_entries",
                               json_object_new_int64(sqlite3_column_int64(st, count_col)));
        json_object_array_add(arr, o);
    }
    sqlite3_finalize(st);
    json_object_object_add(parent, field, arr);
}

static struct json_object *flowd_signature_datasets_load(void)
{
    sqlite3 *db = NULL;
    struct json_object *root = json_object_new_object();
    struct json_object *content = json_object_new_object();
    struct json_object *reputation = json_object_new_object();
    char path[512];
    char source_error[64] = {0};
    enum jmx_system_db_source db_source = JMX_SYSTEM_DB_SOURCE_NONE;
    int content_ready;
    int reputation_ready;

    if (flowd_signature_db_path(path, sizeof(path), &db_source,
                                source_error, sizeof(source_error)) != 0)
        path[0] = '\0';
    json_object_object_add(root, "available", json_object_new_boolean(0));
    json_object_object_add(root, "db_path", json_object_new_string(path));
    json_object_object_add(root, "db_source",
                           json_object_new_string(jmx_system_db_source_name(db_source)));
    json_object_object_add(root, "content", content);
    json_object_object_add(root, "reputation", reputation);

    if (!path[0] || sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
        json_object_object_add(root, "error", json_object_new_string("signature_db_unavailable"));
        json_object_object_add(root, "source_error",
                               json_object_new_string(source_error[0] ? source_error :
                                                      "database_open_failed"));
        json_object_object_add(content, "category_table_present", json_object_new_boolean(0));
        json_object_object_add(content, "domain_table_present", json_object_new_boolean(0));
        json_object_object_add(content, "categories", json_object_new_int64(0));
        json_object_object_add(content, "enabled_categories", json_object_new_int64(0));
        json_object_object_add(content, "domain_entries", json_object_new_int64(0));
        json_object_object_add(content, "enabled_domain_entries", json_object_new_int64(0));
        json_object_object_add(content, "top_categories", json_object_new_array());
        json_object_object_add(content, "state", json_object_new_string("source_unavailable"));
        json_object_object_add(content, "consumer", json_object_new_string("flowd domain/content policy planning"));
        json_object_object_add(reputation, "source_table_present", json_object_new_boolean(0));
        json_object_object_add(reputation, "ip_table_present", json_object_new_boolean(0));
        json_object_object_add(reputation, "domain_table_present", json_object_new_boolean(0));
        json_object_object_add(reputation, "url_table_present", json_object_new_boolean(0));
        json_object_object_add(reputation, "sources", json_object_new_int64(0));
        json_object_object_add(reputation, "ip_entries", json_object_new_int64(0));
        json_object_object_add(reputation, "enabled_ip_entries", json_object_new_int64(0));
        json_object_object_add(reputation, "domain_entries", json_object_new_int64(0));
        json_object_object_add(reputation, "enabled_domain_entries", json_object_new_int64(0));
        json_object_object_add(reputation, "url_entries", json_object_new_int64(0));
        json_object_object_add(reputation, "enabled_url_entries", json_object_new_int64(0));
        json_object_object_add(reputation, "ip_kinds", json_object_new_array());
        json_object_object_add(reputation, "domain_kinds", json_object_new_array());
        json_object_object_add(reputation, "url_kinds", json_object_new_array());
        json_object_object_add(reputation, "state", json_object_new_string("source_unavailable"));
        json_object_object_add(reputation, "consumer", json_object_new_string("routed/logd/identityd risk and set planning"));
        if (db)
            sqlite3_close(db);
        return root;
    }
    sqlite3_busy_timeout(db, 1000);
    json_object_object_del(root, "available");
    json_object_object_add(root, "available", json_object_new_boolean(1));

    flowd_signature_table_state_add(db, content, "category_table_present", "content_category");
    flowd_signature_table_state_add(db, content, "domain_table_present", "content_domain_entry");
    if (flowd_signature_table_exists(db, "content_category")) {
        flowd_signature_count_add(db, content, "categories",
                                  "SELECT COUNT(*) FROM content_category");
        flowd_signature_count_add(db, content, "enabled_categories",
                                  "SELECT COUNT(*) FROM content_category WHERE enabled=1");
    } else {
        json_object_object_add(content, "categories", json_object_new_int64(0));
        json_object_object_add(content, "enabled_categories", json_object_new_int64(0));
    }
    if (flowd_signature_table_exists(db, "content_domain_entry")) {
        flowd_signature_count_add(db, content, "domain_entries",
                                  "SELECT COUNT(*) FROM content_domain_entry");
        flowd_signature_count_add(db, content, "enabled_domain_entries",
                                  "SELECT COUNT(*) FROM content_domain_entry WHERE enabled=1");
        if (flowd_signature_table_exists(db, "content_category"))
            flowd_signature_group_counts_add(db, content, "top_categories",
                "SELECT e.category,COALESCE(c.name,''),COUNT(*) "
                "FROM content_domain_entry e LEFT JOIN content_category c ON c.category=e.category "
                "WHERE e.enabled=1 GROUP BY e.category ORDER BY COUNT(*) DESC,e.category LIMIT 64",
                "category", "name");
        else
            flowd_signature_group_counts_add(db, content, "top_categories",
                "SELECT category,COUNT(*) FROM content_domain_entry WHERE enabled=1 "
                "GROUP BY category ORDER BY COUNT(*) DESC,category LIMIT 64",
                "category", NULL);
    } else {
        json_object_object_add(content, "domain_entries", json_object_new_int64(0));
        json_object_object_add(content, "enabled_domain_entries", json_object_new_int64(0));
        json_object_object_add(content, "top_categories", json_object_new_array());
    }
    content_ready = flowd_json_int64_member(content, "enabled_domain_entries") > 0;
    json_object_object_add(content, "state",
                           json_object_new_string(content_ready ? "ready" : "empty_or_missing"));
    json_object_object_add(content, "consumer", json_object_new_string("flowd domain/content policy planning"));

    flowd_signature_table_state_add(db, reputation, "source_table_present", "reputation_source");
    flowd_signature_table_state_add(db, reputation, "ip_table_present", "reputation_ip_entry");
    flowd_signature_table_state_add(db, reputation, "domain_table_present", "reputation_domain_entry");
    flowd_signature_table_state_add(db, reputation, "url_table_present", "reputation_url_entry");
    if (flowd_signature_table_exists(db, "reputation_source"))
        flowd_signature_count_add(db, reputation, "sources",
                                  "SELECT COUNT(*) FROM reputation_source WHERE enabled=1");
    else
        json_object_object_add(reputation, "sources", json_object_new_int64(0));
    if (flowd_signature_table_exists(db, "reputation_ip_entry")) {
        flowd_signature_count_add(db, reputation, "ip_entries",
                                  "SELECT COUNT(*) FROM reputation_ip_entry");
        flowd_signature_count_add(db, reputation, "enabled_ip_entries",
                                  "SELECT COUNT(*) FROM reputation_ip_entry WHERE enabled=1");
        flowd_signature_group_counts_add(db, reputation, "ip_kinds",
            "SELECT kind,COUNT(*) FROM reputation_ip_entry WHERE enabled=1 "
            "GROUP BY kind ORDER BY COUNT(*) DESC,kind LIMIT 64",
            "kind", NULL);
    } else {
        json_object_object_add(reputation, "ip_entries", json_object_new_int64(0));
        json_object_object_add(reputation, "enabled_ip_entries", json_object_new_int64(0));
        json_object_object_add(reputation, "ip_kinds", json_object_new_array());
    }
    if (flowd_signature_table_exists(db, "reputation_domain_entry")) {
        flowd_signature_count_add(db, reputation, "domain_entries",
                                  "SELECT COUNT(*) FROM reputation_domain_entry");
        flowd_signature_count_add(db, reputation, "enabled_domain_entries",
                                  "SELECT COUNT(*) FROM reputation_domain_entry WHERE enabled=1");
        flowd_signature_group_counts_add(db, reputation, "domain_kinds",
            "SELECT kind,COUNT(*) FROM reputation_domain_entry WHERE enabled=1 "
            "GROUP BY kind ORDER BY COUNT(*) DESC,kind LIMIT 64",
            "kind", NULL);
    } else {
        json_object_object_add(reputation, "domain_entries", json_object_new_int64(0));
        json_object_object_add(reputation, "enabled_domain_entries", json_object_new_int64(0));
        json_object_object_add(reputation, "domain_kinds", json_object_new_array());
    }
    if (flowd_signature_table_exists(db, "reputation_url_entry")) {
        flowd_signature_count_add(db, reputation, "url_entries",
                                  "SELECT COUNT(*) FROM reputation_url_entry");
        flowd_signature_count_add(db, reputation, "enabled_url_entries",
                                  "SELECT COUNT(*) FROM reputation_url_entry WHERE enabled=1");
        flowd_signature_group_counts_add(db, reputation, "url_kinds",
            "SELECT kind,COUNT(*) FROM reputation_url_entry WHERE enabled=1 "
            "GROUP BY kind ORDER BY COUNT(*) DESC,kind LIMIT 64",
            "kind", NULL);
    } else {
        json_object_object_add(reputation, "url_entries", json_object_new_int64(0));
        json_object_object_add(reputation, "enabled_url_entries", json_object_new_int64(0));
        json_object_object_add(reputation, "url_kinds", json_object_new_array());
    }
    reputation_ready = flowd_json_int64_member(reputation, "enabled_ip_entries") > 0 ||
                       flowd_json_int64_member(reputation, "enabled_domain_entries") > 0 ||
                       flowd_json_int64_member(reputation, "enabled_url_entries") > 0;
    json_object_object_add(reputation, "state",
                           json_object_new_string(reputation_ready ? "ready" : "empty_or_missing"));
    json_object_object_add(reputation, "consumer", json_object_new_string("routed/logd/identityd risk and set planning"));

    sqlite3_close(db);
    return root;
}

static struct json_object *flowd_country_stats_get_or_add(struct json_object *countries,
                                                          const char *iso)
{
    struct json_object *country = NULL;

    if (!countries || !iso || !iso[0])
        return NULL;
    if (json_object_object_get_ex(countries, iso, &country) && country)
        return country;
    country = json_object_new_object();
    json_object_object_add(country, "iso_code", json_object_new_string(iso));
    json_object_object_add(country, "ipv4_prefixes", json_object_new_int64(0));
    json_object_object_add(country, "ipv6_prefixes", json_object_new_int64(0));
    json_object_object_add(country, "total_prefixes", json_object_new_int64(0));
    json_object_object_add(countries, iso, country);
    return country;
}

static struct json_object *flowd_country_prefix_index_load(void)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *st = NULL;
    struct json_object *idx = json_object_new_object();
    struct json_object *countries = json_object_new_object();
    char path[512];
    char source_error[64] = {0};
    enum jmx_system_db_source db_source = JMX_SYSTEM_DB_SOURCE_NONE;
    int64_t total = 0;
    int64_t ipv4_total = 0;
    int64_t ipv6_total = 0;
    int available = 0;
    int rc;

    if (flowd_signature_db_path(path, sizeof(path), &db_source,
                                source_error, sizeof(source_error)) != 0)
        path[0] = '\0';
    json_object_object_add(idx, "available", json_object_new_boolean(0));
    json_object_object_add(idx, "db_path", json_object_new_string(path));
    json_object_object_add(idx, "db_source",
                           json_object_new_string(jmx_system_db_source_name(db_source)));
    json_object_object_add(idx, "source_table", json_object_new_string("geoip_country_prefix"));
    json_object_object_add(idx, "total_prefixes", json_object_new_int64(0));
    json_object_object_add(idx, "ipv4_prefixes", json_object_new_int64(0));
    json_object_object_add(idx, "ipv6_prefixes", json_object_new_int64(0));
    json_object_object_add(idx, "countries", countries);

    if (!path[0] || sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
        json_object_object_add(idx, "error", json_object_new_string("signature_db_unavailable"));
        json_object_object_add(idx, "source_error",
                               json_object_new_string(source_error[0] ? source_error :
                                                      "database_open_failed"));
        if (db)
            sqlite3_close(db);
        return idx;
    }
    sqlite3_busy_timeout(db, 1000);
    if (!flowd_signature_table_exists(db, "geoip_country_prefix")) {
        json_object_object_add(idx, "error", json_object_new_string("geoip_country_prefix_missing"));
        sqlite3_close(db);
        return idx;
    }
    if (sqlite3_prepare_v2(db,
        "SELECT iso_code,family,COUNT(*) FROM geoip_country_prefix "
        "WHERE enabled=1 GROUP BY iso_code,family ORDER BY iso_code,family",
        -1, &st, NULL) != SQLITE_OK) {
        json_object_object_add(idx, "error", json_object_new_string("geoip_country_prefix_query_prepare_failed"));
        sqlite3_close(db);
        return idx;
    }
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        const char *iso = (const char *)sqlite3_column_text(st, 0);
        int family = sqlite3_column_int(st, 1);
        int64_t count = sqlite3_column_int64(st, 2);
        struct json_object *country;
        const char *key;

        if (!iso || !iso[0] || count <= 0 || (family != 4 && family != 6))
            continue;
        country = flowd_country_stats_get_or_add(countries, iso);
        if (!country)
            continue;
        key = family == 4 ? "ipv4_prefixes" : "ipv6_prefixes";
        flowd_json_set_int64(country, key, flowd_json_int64_member(country, key) + count);
        flowd_json_set_int64(country, "total_prefixes",
                             flowd_json_int64_member(country, "total_prefixes") + count);
        total += count;
        if (family == 4)
            ipv4_total += count;
        else
            ipv6_total += count;
    }
    if (rc == SQLITE_DONE)
        available = 1;
    else
        json_object_object_add(idx, "error", json_object_new_string("geoip_country_prefix_query_failed"));

    sqlite3_finalize(st);
    sqlite3_close(db);
    json_object_object_del(idx, "available");
    json_object_object_add(idx, "available", json_object_new_boolean(available));
    flowd_json_set_int64(idx, "total_prefixes", total);
    flowd_json_set_int64(idx, "ipv4_prefixes", ipv4_total);
    flowd_json_set_int64(idx, "ipv6_prefixes", ipv6_total);
    return idx;
}

static int64_t flowd_country_prefix_count(struct json_object *prefix_index,
                                          const char *iso, int family)
{
    struct json_object *countries = NULL;
    struct json_object *country = NULL;

    if (!prefix_index || !iso || !iso[0])
        return 0;
    if (!json_object_object_get_ex(prefix_index, "countries", &countries) || !countries)
        return 0;
    if (!json_object_object_get_ex(countries, iso, &country) || !country)
        return 0;
    return flowd_json_int64_member(country, family == 6 ? "ipv6_prefixes" : "ipv4_prefixes");
}

static int flowd_country_prefix_index_available(struct json_object *prefix_index)
{
    struct json_object *v = NULL;

    return prefix_index && json_object_object_get_ex(prefix_index, "available", &v) &&
           json_object_get_boolean(v);
}

static void flowd_country_set_name(char *out, size_t out_len, const char *iso, int family)
{
    char a = iso && iso[0] ? (char)tolower((unsigned char)iso[0]) : 'x';
    char b = iso && iso[1] ? (char)tolower((unsigned char)iso[1]) : 'x';

    snprintf(out, out_len, "dwrt_geoip_%c%c_v%d", a, b, family);
}

static void flowd_country_set_plan_add(struct json_object *sets, struct json_object *seen,
                                       struct json_object *prefix_index,
                                       const char *policy_id, const char *iso, int family)
{
    struct json_object *existing = NULL;
    struct json_object *o;
    struct json_object *policies;
    char key[32];
    char set_name[64];
    int64_t count;
    int prefix_available;

    if (!sets || !seen || !iso || !iso[0] || (family != 4 && family != 6))
        return;
    snprintf(key, sizeof(key), "%s_v%d", iso, family);
    if (json_object_object_get_ex(seen, key, &existing) && existing) {
        if (policy_id && policy_id[0] &&
            json_object_object_get_ex(existing, "policy_ids", &policies) && policies)
            json_object_array_add(policies, json_object_new_string(policy_id));
        return;
    }
    flowd_country_set_name(set_name, sizeof(set_name), iso, family);
    count = flowd_country_prefix_count(prefix_index, iso, family);
    prefix_available = flowd_country_prefix_index_available(prefix_index);

    policies = json_object_new_array();
    if (policy_id && policy_id[0])
        json_object_array_add(policies, json_object_new_string(policy_id));
    o = json_object_new_object();
    json_object_object_add(o, "country", json_object_new_string(iso));
    json_object_object_add(o, "family", json_object_new_string(family == 6 ? "ipv6" : "ipv4"));
    json_object_object_add(o, "nft_set", json_object_new_string(set_name));
    json_object_object_add(o, "prefix_count", json_object_new_int64(count));
    json_object_object_add(o, "source_table", json_object_new_string("geoip_country_prefix"));
    json_object_object_add(o, "policy_ids", policies);
    json_object_object_add(o, "state",
                           json_object_new_string(!prefix_available ? "source_unavailable" :
                                                  count > 0 ? "ready" : "empty"));
    json_object_object_add(o, "mutates_dataplane", json_object_new_boolean(0));
    json_object_object_add(seen, key, json_object_get(o));
    json_object_array_add(sets, o);
}

static struct json_object *flowd_country_sets_plan_from_policies(struct json_object *policies,
                                                                 struct json_object *prefix_index)
{
    struct json_object *sets = json_object_new_array();
    struct json_object *seen = json_object_new_object();
    int i, n;

    if (!policies || !json_object_is_type(policies, json_type_array)) {
        json_object_put(seen);
        return sets;
    }
    n = json_object_array_length(policies);
    for (i = 0; i < n; i++) {
        struct json_object *p = json_object_array_get_idx(policies, i);
        struct json_object *countries = NULL;
        const char *policy_id;
        const char *family;
        int j, m;

        if (!p || !json_object_is_type(p, json_type_object))
            continue;
        policy_id = flowd_json_str(p, "id", "");
        family = flowd_policy_family(flowd_json_str(p, "family", "both"));
        if (!family)
            family = "both";
        if (!json_object_object_get_ex(p, "countries", &countries) || !countries ||
            !json_object_is_type(countries, json_type_array))
            continue;
        m = json_object_array_length(countries);
        for (j = 0; j < m; j++) {
            struct json_object *v = json_object_array_get_idx(countries, j);
            const char *iso = v && json_object_is_type(v, json_type_string) ?
                              json_object_get_string(v) : NULL;

            if (!iso || !iso[0])
                continue;
            if (!strcmp(family, "ipv4") || !strcmp(family, "both"))
                flowd_country_set_plan_add(sets, seen, prefix_index, policy_id, iso, 4);
            if (!strcmp(family, "ipv6") || !strcmp(family, "both"))
                flowd_country_set_plan_add(sets, seen, prefix_index, policy_id, iso, 6);
        }
    }
    json_object_put(seen);
    return sets;
}

struct json_object *flowd_country_policies_json(void)
{
    sqlite3_stmt *st;
    struct json_object *resp = json_object_new_object();
    struct json_object *arr = json_object_new_array();
    int ok = 0;
    int rc;

    st = flowd_config_prepare(
        "SELECT id,name,enabled,priority,direction,countries_json,action,target,family,remark,updated_at "
        "FROM flowd_country_policies ORDER BY priority,id");
    if (st) {
        while ((rc = sqlite3_step(st)) == SQLITE_ROW)
            flowd_policy_row_json(arr, st);
        ok = rc == SQLITE_DONE;
        if (!ok)
            fprintf(stderr, "[dreamingwrt-flowd] country policies query failed: %s\n",
                    g_flowd_config_db ? sqlite3_errmsg(g_flowd_config_db) : "database unavailable");
        sqlite3_finalize(st);
    }
    json_object_object_add(resp, "ok", json_object_new_boolean(ok));
    json_object_object_add(resp, "policies", arr);
    if (!ok)
        json_object_object_add(resp, "error", json_object_new_string("country_policies_unavailable"));
    return resp;
}

static int flowd_country_policy_load_existing(const char *id,
                                              char *name, size_t name_len,
                                              int *enabled, int *priority,
                                              char *direction, size_t direction_len,
                                              char *countries_json, size_t countries_json_len,
                                              char *action, size_t action_len,
                                              char *target, size_t target_len,
                                              char *family, size_t family_len,
                                              char *remark, size_t remark_len)
{
    sqlite3_stmt *st;
    int rc;

    if (!flowd_id_ok(id))
        return -1;
    st = flowd_config_prepare(
        "SELECT name,enabled,priority,direction,countries_json,action,target,family,remark "
        "FROM flowd_country_policies WHERE id=?1");
    if (!st)
        return -1;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) {
        snprintf(name, name_len, "%s",
                 sqlite3_column_text(st, 0) ? (const char *)sqlite3_column_text(st, 0) : "");
        if (enabled)
            *enabled = sqlite3_column_int(st, 1) ? 1 : 0;
        if (priority)
            *priority = sqlite3_column_int(st, 2);
        snprintf(direction, direction_len, "%s",
                 sqlite3_column_text(st, 3) ? (const char *)sqlite3_column_text(st, 3) : "dst");
        snprintf(countries_json, countries_json_len, "%s",
                 sqlite3_column_text(st, 4) ? (const char *)sqlite3_column_text(st, 4) : "[]");
        snprintf(action, action_len, "%s",
                 sqlite3_column_text(st, 5) ? (const char *)sqlite3_column_text(st, 5) : "route");
        snprintf(target, target_len, "%s",
                 sqlite3_column_text(st, 6) ? (const char *)sqlite3_column_text(st, 6) : "");
        snprintf(family, family_len, "%s",
                 sqlite3_column_text(st, 7) ? (const char *)sqlite3_column_text(st, 7) : "both");
        snprintf(remark, remark_len, "%s",
                 sqlite3_column_text(st, 8) ? (const char *)sqlite3_column_text(st, 8) : "");
        sqlite3_finalize(st);
        return 1;
    }
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

static int flowd_country_policy_save_one(struct json_object *p)
{
    sqlite3_stmt *st;
    struct json_object *countries = NULL;
    char generated_id[FLOWD_MAX_ID];
    char countries_json[FLOWD_MAX_JSON];
    char name_buf[129] = "";
    char direction_buf[16] = "dst";
    char countries_json_buf[FLOWD_MAX_JSON + 1] = "[]";
    char action_buf[32] = "route";
    char target_buf[129] = "";
    char family_buf[16] = "both";
    char remark_buf[257] = "";
    const char *id, *name, *direction, *action, *target, *family, *remark;
    int enabled, priority, countries_owned = 0, ok = 0;
    int64_t now = flowd_now_s();

    if (!p || !json_object_is_type(p, json_type_object))
        return -1;
    enabled = 1;
    priority = 1000;
    id = flowd_json_str(p, "id", "");
    if (!id[0]) {
        flowd_make_id("country-policy", generated_id, sizeof(generated_id));
        id = generated_id;
    } else {
        int existing;

        existing = flowd_country_policy_load_existing(id, name_buf, sizeof(name_buf),
                                                      &enabled, &priority,
                                                      direction_buf, sizeof(direction_buf),
                                                      countries_json_buf, sizeof(countries_json_buf),
                                                      action_buf, sizeof(action_buf),
                                                      target_buf, sizeof(target_buf),
                                                      family_buf, sizeof(family_buf),
                                                      remark_buf, sizeof(remark_buf));
        if (existing < 0)
            return -1;
    }
    name = flowd_json_str(p, "name", name_buf);
    enabled = flowd_json_bool(p, "enabled", enabled);
    priority = flowd_json_int(p, "priority", priority);
    direction = flowd_policy_direction(flowd_json_str(p, "direction", direction_buf));
    action = flowd_policy_action(flowd_json_str(p, "action", action_buf));
    target = flowd_json_str(p, "target", target_buf);
    family = flowd_policy_family(flowd_json_str(p, "family", family_buf));
    remark = flowd_json_str(p, "remark", remark_buf);
    if (!json_object_object_get_ex(p, "countries", &countries) || !countries)
        json_object_object_get_ex(p, "countries_json", &countries);
    if (!countries) {
        countries = json_tokener_parse(countries_json_buf);
        countries_owned = countries ? 1 : 0;
    }
    if (!countries) {
        countries = json_object_new_array();
        countries_owned = countries ? 1 : 0;
    }
    if (!flowd_id_ok(id) || !flowd_text_ok(name, 128) || !direction || !action || !family ||
        !flowd_token_ok(target[0] ? target : "none", 128) || !flowd_text_ok(remark, 256) ||
        priority < 1 || priority > 100000 ||
        flowd_countries_normalize(countries, countries_json, sizeof(countries_json), NULL) != 0) {
        if (countries_owned && countries)
            json_object_put(countries);
        return -1;
    }

    st = flowd_config_prepare(
        "INSERT INTO flowd_country_policies"
        "(id,name,enabled,priority,direction,countries_json,action,target,family,remark,created_at,updated_at) "
        "VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?11) "
        "ON CONFLICT(id) DO UPDATE SET name=excluded.name,enabled=excluded.enabled,"
        "priority=excluded.priority,direction=excluded.direction,countries_json=excluded.countries_json,"
        "action=excluded.action,target=excluded.target,family=excluded.family,remark=excluded.remark,"
        "updated_at=excluded.updated_at");
    if (st) {
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, name, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 3, enabled ? 1 : 0);
        sqlite3_bind_int(st, 4, priority);
        sqlite3_bind_text(st, 5, direction, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 6, countries_json, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 7, action, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 8, target, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 9, family, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 10, remark, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 11, now);
        ok = sqlite3_step(st) == SQLITE_DONE;
        sqlite3_finalize(st);
    }
    if (countries_owned && countries)
        json_object_put(countries);
    return ok ? 0 : -1;
}

struct json_object *flowd_country_policy_update(struct json_object *body)
{
    struct json_object *arr = NULL;
    int ok = 1, saved = 0, i, n;
    struct json_object *resp;

    if (!body || !json_object_is_type(body, json_type_object))
        return flowd_error("invalid_request", "country policy body must be an object");
    if (json_object_object_get_ex(body, "policies", &arr) && arr &&
        json_object_is_type(arr, json_type_array)) {
        n = json_object_array_length(arr);
        for (i = 0; i < n; i++) {
            if (flowd_country_policy_save_one(json_object_array_get_idx(arr, i)) == 0)
                saved++;
            else
                ok = 0;
        }
    } else {
        ok = flowd_country_policy_save_one(body) == 0;
        saved = ok ? 1 : 0;
    }
    resp = flowd_country_policies_json();
    flowd_response_set_ok(resp, ok);
    json_object_object_add(resp, "saved", json_object_new_int(saved));
    if (!ok)
        json_object_object_add(resp, "error", json_object_new_string("partial_or_failed_save"));
    return resp;
}

struct json_object *flowd_country_policy_delete(struct json_object *body)
{
    sqlite3_stmt *st;
    const char *id = flowd_json_str(body, "id", "");
    int ok = 0;
    struct json_object *resp;

    if (!flowd_id_ok(id))
        return flowd_error("invalid_id", "invalid country policy id");
    st = flowd_config_prepare("DELETE FROM flowd_country_policies WHERE id=?1");
    if (st) {
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        ok = sqlite3_step(st) == SQLITE_DONE && sqlite3_changes(g_flowd_config_db) > 0;
        sqlite3_finalize(st);
    }
    resp = flowd_country_policies_json();
    flowd_response_set_ok(resp, ok);
    json_object_object_add(resp, "deleted", json_object_new_boolean(ok));
    if (!ok)
        json_object_object_add(resp, "error", json_object_new_string("not_found"));
    return resp;
}

static int flowd_write_json_atomic(const char *path, struct json_object *obj)
{
    char tmp[FLOWD_MAX_TEXT + 64];
    const char *s;
    FILE *fp;
    int rc = -1;

    if (!path || !path[0] || !flowd_path_ok(path) || !obj)
        return -1;
    snprintf(tmp, sizeof(tmp), "%s.tmp.%u", path, (unsigned)getpid());
    fp = fopen(tmp, "w");
    if (!fp)
        return -1;
    s = json_object_to_json_string_ext(obj, JSON_C_TO_STRING_PRETTY);
    if (s && fputs(s, fp) >= 0 && fputc('\n', fp) != EOF && fflush(fp) == 0 &&
        fsync(fileno(fp)) == 0)
        rc = 0;
    if (fclose(fp) != 0)
        rc = -1;
    if (rc == 0) {
        if (rename(tmp, path) != 0)
            rc = -1;
    }
    if (rc != 0)
        unlink(tmp);
    return rc;
}

static int flowd_join_path(char *out, size_t out_len, const char *dir, const char *leaf)
{
    size_t dir_len;
    size_t leaf_len;

    if (!out || out_len == 0 || !dir || !dir[0] || !flowd_path_ok(dir) || !leaf || !leaf[0] ||
        strchr(leaf, '/') || !flowd_token_ok(leaf, 160))
        return -1;
    dir_len = strlen(dir);
    while (dir_len > 1 && dir[dir_len - 1] == '/')
        dir_len--;
    leaf_len = strlen(leaf);
    if (dir_len + (dir_len > 1 ? 1 : 0) + leaf_len >= out_len)
        return -1;
    memcpy(out, dir, dir_len);
    if (dir_len > 1)
        out[dir_len++] = '/';
    memcpy(out + dir_len, leaf, leaf_len + 1);
    return flowd_path_ok(out) ? 0 : -1;
}

struct json_object *flowd_country_sets_generate(struct json_object *body)
{
    struct flowd_settings s;
    sqlite3_stmt *st;
    struct json_object *resp = json_object_new_object();
    struct json_object *plan = json_object_new_object();
    struct json_object *policies = json_object_new_array();
    struct json_object *prefix_index;
    struct json_object *country_sets;
    char plan_path[FLOWD_MAX_TEXT + 64];
    int write_plan;
    int written = 0;
    int settings_available;
    int ok = 1;
    int rc;
    const char *error = "";

    settings_available = flowd_settings_load(&s) == 0;
    if (!settings_available) {
        flowd_settings_defaults(&s);
        ok = 0;
        error = "settings_unavailable";
    }
    write_plan = flowd_json_bool(body, "write", 0);
    if (!settings_available)
        write_plan = 0;
    st = flowd_config_prepare(
        "SELECT id,name,enabled,priority,direction,countries_json,action,target,family,remark,updated_at "
        "FROM flowd_country_policies WHERE enabled=1 ORDER BY priority,id");
    if (st) {
        while ((rc = sqlite3_step(st)) == SQLITE_ROW)
            flowd_policy_row_json(policies, st);
        if (rc != SQLITE_DONE) {
            ok = 0;
            if (!error[0])
                error = "country_policies_unavailable";
        }
        sqlite3_finalize(st);
    } else {
        ok = 0;
        if (!error[0])
            error = "country_policies_unavailable";
    }
    prefix_index = flowd_country_prefix_index_load();
    country_sets = flowd_country_sets_plan_from_policies(policies, prefix_index);
    json_object_object_add(plan, "version", json_object_new_int(FLOWD_SCHEMA_VERSION));
    json_object_object_add(plan, "generated_at", json_object_new_int64(flowd_now_s()));
    json_object_object_add(plan, "settings_available", json_object_new_boolean(settings_available));
    json_object_object_add(plan, "apply_mode", json_object_new_string(s.apply_mode));
    json_object_object_add(plan, "runtime_dir", json_object_new_string(s.runtime_dir));
    json_object_object_add(plan, "note", json_object_new_string("control-plane plan only; firewall/nft apply is intentionally separate"));
    json_object_object_add(plan, "prefix_index", prefix_index);
    json_object_object_add(plan, "country_sets", country_sets);
    json_object_object_add(plan, "policies", policies);

    if (flowd_join_path(plan_path, sizeof(plan_path), s.runtime_dir,
                        "country-routing-plan.json") != 0)
        plan_path[0] = '\0';
    if (write_plan) {
        written = flowd_mkdir_p(s.runtime_dir, 0755) == 0 &&
                  flowd_write_json_atomic(plan_path, plan) == 0;
        if (!written) {
            ok = 0;
            if (!error[0])
                error = "write_failed";
        }
    }
    json_object_object_add(resp, "ok", json_object_new_boolean(ok));
    json_object_object_add(resp, "plan_path", json_object_new_string(plan_path));
    json_object_object_add(resp, "written", json_object_new_boolean(written));
    json_object_object_add(resp, "plan", plan);
    if (error[0])
        json_object_object_add(resp, "error", json_object_new_string(error));
    return resp;
}

static int flowd_object_type_ok(const char *type)
{
    return type && (!strcmp(type, "ipv4") || !strcmp(type, "ipv6") ||
                    !strcmp(type, "mac") || !strcmp(type, "port") ||
                    !strcmp(type, "time") || !strcmp(type, "protocol") ||
                    !strcmp(type, "domain") || !strcmp(type, "app_set") ||
                    !strcmp(type, "country") || !strcmp(type, "isp"));
}

static const char *flowd_object_runtime_kind(const char *type)
{
    if (!strcmp(type, "ipv4") || !strcmp(type, "ipv6") || !strcmp(type, "country") ||
        !strcmp(type, "isp"))
        return "nft_set";
    if (!strcmp(type, "mac"))
        return "nft_ether_set";
    if (!strcmp(type, "port") || !strcmp(type, "protocol"))
        return "match_set";
    if (!strcmp(type, "time"))
        return "schedule_set";
    if (!strcmp(type, "domain"))
        return "domain_set";
    if (!strcmp(type, "app_set"))
        return "app_set";
    return "object_set";
}

static struct json_object *flowd_json_parse_or_value(const char *s)
{
    struct json_object *o = NULL;

    if (s && s[0])
        o = json_tokener_parse(s);
    return o ? o : json_object_new_array();
}

static int flowd_json_value_count(struct json_object *o)
{
    if (!o)
        return 0;
    if (json_object_is_type(o, json_type_array))
        return json_object_array_length(o);
    if (json_object_is_type(o, json_type_object))
        return json_object_object_length(o);
    return 1;
}

static struct json_object *flowd_object_references_json(const char *object_id,
                                                        int *count_out)
{
    static const char sql[] =
        "SELECT 'split_rule',id,name,'src_object',enabled FROM flowd_split_rules WHERE src_object=?1 "
        "UNION ALL SELECT 'split_rule',id,name,'dst_object',enabled FROM flowd_split_rules WHERE dst_object=?1 "
        "UNION ALL SELECT 'split_rule',id,name,'app_object',enabled FROM flowd_split_rules WHERE app_object=?1 "
        "UNION ALL SELECT 'split_rule',id,name,'service_object',enabled FROM flowd_split_rules WHERE service_object=?1 "
        "UNION ALL SELECT 'split_rule',id,name,'time_object',enabled FROM flowd_split_rules WHERE time_object=?1 "
        "UNION ALL SELECT 'domain_rule',id,name,'domain_object',enabled FROM flowd_domain_rules WHERE domain_object=?1 "
        "UNION ALL SELECT 'domain_rule',id,name,'src_object',enabled FROM flowd_domain_rules WHERE src_object=?1 "
        "UNION ALL SELECT 'domain_rule',id,name,'time_object',enabled FROM flowd_domain_rules WHERE time_object=?1 "
        "UNION ALL SELECT 'qos_rule',id,name,'src_object',enabled FROM flowd_qos_rules WHERE src_object=?1 "
        "UNION ALL SELECT 'qos_rule',id,name,'dst_object',enabled FROM flowd_qos_rules WHERE dst_object=?1 "
        "UNION ALL SELECT 'qos_rule',id,name,'app_object',enabled FROM flowd_qos_rules WHERE app_object=?1 "
        "UNION ALL SELECT 'qos_rule',id,name,'service_object',enabled FROM flowd_qos_rules WHERE service_object=?1 "
        "UNION ALL SELECT 'qos_rule',id,name,'time_object',enabled FROM flowd_qos_rules WHERE time_object=?1 "
        "UNION ALL SELECT 'quota_rule',id,name,'target_object',enabled FROM flowd_quota_rules WHERE target_object=?1 "
        "UNION ALL SELECT 'conn_limit_rule',id,name,'src_object',enabled FROM flowd_conn_limit_rules WHERE src_object=?1 "
        "UNION ALL SELECT 'conn_limit_rule',id,name,'dst_object',enabled FROM flowd_conn_limit_rules WHERE dst_object=?1 "
        "UNION ALL SELECT 'conn_limit_rule',id,name,'service_object',enabled FROM flowd_conn_limit_rules WHERE service_object=?1 "
        "UNION ALL SELECT 'conn_limit_rule',id,name,'time_object',enabled FROM flowd_conn_limit_rules WHERE time_object=?1 "
        "UNION ALL SELECT 'app_rule',id,name,'src_object',enabled FROM flowd_app_rules WHERE src_object=?1 "
        "UNION ALL SELECT 'app_rule',id,name,'app_object',enabled FROM flowd_app_rules WHERE app_object=?1 "
        "UNION ALL SELECT 'app_rule',id,name,'time_object',enabled FROM flowd_app_rules WHERE time_object=?1 "
        "ORDER BY 1,2,4";
    struct json_object *references = json_object_new_array();
    sqlite3_stmt *st = NULL;
    int count = 0;

    if (count_out)
        *count_out = 0;
    if (!references || !flowd_id_ok(object_id))
        return references;
    st = flowd_config_prepare(sql);
    if (!st)
        return references;
    sqlite3_bind_text(st, 1, object_id, -1, SQLITE_TRANSIENT);
    while (sqlite3_step(st) == SQLITE_ROW) {
        struct json_object *ref = json_object_new_object();

        json_object_object_add(ref, "kind", flowd_sqlite_text_json(st, 0));
        json_object_object_add(ref, "id", flowd_sqlite_text_json(st, 1));
        json_object_object_add(ref, "name", flowd_sqlite_text_json(st, 2));
        json_object_object_add(ref, "field", flowd_sqlite_text_json(st, 3));
        json_object_object_add(ref, "enabled",
                               json_object_new_boolean(sqlite3_column_int(st, 4)));
        json_object_array_add(references, ref);
        count++;
    }
    sqlite3_finalize(st);
    if (count_out)
        *count_out = count;
    return references;
}

static struct json_object *flowd_object_value_from_body(struct json_object *body)
{
    struct json_object *v = NULL;
    struct json_object *parsed = NULL;

    if (!body || !json_object_is_type(body, json_type_object))
        return json_object_new_array();
    if (!json_object_object_get_ex(body, "value", &v) &&
        !json_object_object_get_ex(body, "values", &v) &&
        !json_object_object_get_ex(body, "value_json", &v))
        return json_object_new_array();
    if (v && json_object_is_type(v, json_type_string)) {
        parsed = json_tokener_parse(json_object_get_string(v));
        if (parsed)
            return parsed;
    }
    return v ? json_object_get(v) : json_object_new_array();
}

static void flowd_object_row_json(struct json_object *arr, sqlite3_stmt *st)
{
    const char *id = (const char *)sqlite3_column_text(st, 0);
    const char *type = (const char *)sqlite3_column_text(st, 1);
    const char *value_s = (const char *)sqlite3_column_text(st, 4);
    struct json_object *value = flowd_json_parse_or_value(value_s);
    struct json_object *o = json_object_new_object();
    struct json_object *references;
    int reference_count = 0;

    json_object_object_add(o, "id", json_object_new_string(id ? id : ""));
    json_object_object_add(o, "type", json_object_new_string(type ? type : ""));
    json_object_object_add(o, "name", flowd_sqlite_text_json(st, 2));
    json_object_object_add(o, "enabled", json_object_new_boolean(sqlite3_column_int(st, 3)));
    json_object_object_add(o, "value", value);
    json_object_object_add(o, "value_count", json_object_new_int(flowd_json_value_count(value)));
    json_object_object_add(o, "runtime_kind", json_object_new_string(type ? flowd_object_runtime_kind(type) : "object_set"));
    json_object_object_add(o, "remark", flowd_sqlite_text_json(st, 5));
    json_object_object_add(o, "updated_at", json_object_new_int64(sqlite3_column_int64(st, 6)));
    references = flowd_object_references_json(id, &reference_count);
    json_object_object_add(o, "reference_count", json_object_new_int(reference_count));
    json_object_object_add(o, "delete_locked", json_object_new_boolean(reference_count > 0));
    json_object_object_add(o, "referenced_by", references);
    json_object_array_add(arr, o);
}

struct json_object *flowd_objects_json(struct json_object *body)
{
    sqlite3_stmt *st = NULL;
    struct json_object *resp = json_object_new_object();
    struct json_object *arr = json_object_new_array();
    const char *id = flowd_json_str(body, "id", "");
    const char *type = flowd_json_str(body, "type", "");
    int include_disabled = flowd_json_bool(body, "include_disabled", 1);
    int ok = 1;
    const char *error = "";

    if (id && id[0] && !flowd_id_ok(id))
        return flowd_error("invalid_id", "invalid flowd object id");
    if (type && type[0] && !flowd_object_type_ok(type))
        return flowd_error("invalid_type", "invalid flowd object type");
    if (id && id[0]) {
        st = flowd_config_prepare(
            "SELECT id,type,name,enabled,value_json,remark,updated_at FROM flowd_objects WHERE id=?1");
        if (st)
            sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    } else if (type && type[0]) {
        st = flowd_config_prepare(
            "SELECT id,type,name,enabled,value_json,remark,updated_at FROM flowd_objects "
            "WHERE type=?1 AND (?2 OR enabled=1) ORDER BY type,id");
        if (st) {
            sqlite3_bind_text(st, 1, type, -1, SQLITE_TRANSIENT);
            sqlite3_bind_int(st, 2, include_disabled ? 1 : 0);
        }
    } else {
        st = flowd_config_prepare(
            "SELECT id,type,name,enabled,value_json,remark,updated_at FROM flowd_objects "
            "WHERE (?1 OR enabled=1) ORDER BY type,id");
        if (st)
            sqlite3_bind_int(st, 1, include_disabled ? 1 : 0);
    }
    if (st) {
        ok = flowd_collect_rows(st, arr, flowd_object_row_json, "objects");
        if (!ok)
            error = "objects_unavailable";
        sqlite3_finalize(st);
    } else {
        ok = 0;
        error = "objects_unavailable";
    }
    flowd_list_total_add(resp, &ok, &error, "SELECT COUNT(*) FROM flowd_objects",
                         "objects_count_unavailable");
    json_object_object_add(resp, "ok", json_object_new_boolean(ok));
    json_object_object_add(resp, "objects", arr);
    if (error[0])
        json_object_object_add(resp, "error", json_object_new_string(error));
    return resp;
}

static int flowd_object_load_existing(const char *id,
                                      char *type, size_t type_len,
                                      char *name, size_t name_len,
                                      int *enabled,
                                      char *value_json, size_t value_json_len,
                                      char *remark, size_t remark_len)
{
    sqlite3_stmt *st;
    int rc;

    if (!flowd_id_ok(id))
        return -1;
    st = flowd_config_prepare(
        "SELECT type,name,enabled,value_json,remark FROM flowd_objects WHERE id=?1");
    if (!st)
        return -1;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) {
        snprintf(type, type_len, "%s",
                 sqlite3_column_text(st, 0) ? (const char *)sqlite3_column_text(st, 0) : "ipv4");
        snprintf(name, name_len, "%s",
                 sqlite3_column_text(st, 1) ? (const char *)sqlite3_column_text(st, 1) : "");
        if (enabled)
            *enabled = sqlite3_column_int(st, 2) ? 1 : 0;
        snprintf(value_json, value_json_len, "%s",
                 sqlite3_column_text(st, 3) ? (const char *)sqlite3_column_text(st, 3) : "[]");
        snprintf(remark, remark_len, "%s",
                 sqlite3_column_text(st, 4) ? (const char *)sqlite3_column_text(st, 4) : "");
        sqlite3_finalize(st);
        return 1;
    }
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

static int flowd_object_save_one(struct json_object *body)
{
    sqlite3_stmt *st;
    struct json_object *value = NULL;
    struct json_object *value_body = NULL;
    char generated_id[FLOWD_MAX_ID];
    char normalized_country[FLOWD_MAX_JSON];
    char type_buf[32] = "ipv4";
    char name_buf[129] = "";
    char value_json_buf[FLOWD_MAX_JSON + 1] = "[]";
    char remark_buf[257] = "";
    const char *id, *type, *name, *remark, *value_s;
    int enabled, ok = 0;
    int64_t now = flowd_now_s();

    if (!body || !json_object_is_type(body, json_type_object))
        return -1;
    enabled = 1;
    id = flowd_json_str(body, "id", "");
    if (!id[0]) {
        flowd_make_id("object", generated_id, sizeof(generated_id));
        id = generated_id;
    } else {
        int existing;

        existing = flowd_object_load_existing(id, type_buf, sizeof(type_buf),
                                             name_buf, sizeof(name_buf), &enabled,
                                             value_json_buf, sizeof(value_json_buf),
                                             remark_buf, sizeof(remark_buf));
        if (existing < 0)
            return -1;
    }
    type = flowd_json_str(body, "type", type_buf);
    name = flowd_json_str(body, "name", name_buf);
    remark = flowd_json_str(body, "remark", remark_buf);
    enabled = flowd_json_bool(body, "enabled", enabled);
    if (json_object_object_get_ex(body, "value", &value_body) ||
        json_object_object_get_ex(body, "values", &value_body) ||
        json_object_object_get_ex(body, "value_json", &value_body)) {
        value = flowd_object_value_from_body(body);
    } else {
        value = flowd_json_parse_or_value(value_json_buf);
    }
    if (!flowd_id_ok(id) || !flowd_object_type_ok(type) || !flowd_text_ok(name, 128) ||
        !flowd_text_ok(remark, 256) || !flowd_json_fits(value, FLOWD_MAX_JSON)) {
        if (value)
            json_object_put(value);
        return -1;
    }
    if (!strcmp(type, "country")) {
        if (flowd_countries_normalize(value, normalized_country, sizeof(normalized_country), NULL) != 0) {
            json_object_put(value);
            return -1;
        }
        value_s = normalized_country;
    } else {
        value_s = json_object_to_json_string_ext(value, JSON_C_TO_STRING_PLAIN);
        if (!value_s) {
            json_object_put(value);
            return -1;
        }
    }
    st = flowd_config_prepare(
        "INSERT INTO flowd_objects(id,type,name,enabled,value_json,remark,created_at,updated_at) "
        "VALUES(?1,?2,?3,?4,?5,?6,?7,?7) "
        "ON CONFLICT(id) DO UPDATE SET type=excluded.type,name=excluded.name,"
        "enabled=excluded.enabled,value_json=excluded.value_json,remark=excluded.remark,"
        "updated_at=excluded.updated_at");
    if (st) {
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, type, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 3, name, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 4, enabled ? 1 : 0);
        sqlite3_bind_text(st, 5, value_s, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 6, remark, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 7, now);
        ok = sqlite3_step(st) == SQLITE_DONE;
        sqlite3_finalize(st);
    }
    json_object_put(value);
    return ok ? 0 : -1;
}

struct json_object *flowd_object_update(struct json_object *body)
{
    struct json_object *arr = NULL;
    int ok = 1, saved = 0, i, n;
    struct json_object *resp;

    if (!body || !json_object_is_type(body, json_type_object))
        return flowd_error("invalid_request", "flowd object body must be an object");
    if (json_object_object_get_ex(body, "objects", &arr) && arr &&
        json_object_is_type(arr, json_type_array)) {
        n = json_object_array_length(arr);
        for (i = 0; i < n; i++) {
            if (flowd_object_save_one(json_object_array_get_idx(arr, i)) == 0)
                saved++;
            else
                ok = 0;
        }
    } else {
        ok = flowd_object_save_one(body) == 0;
        saved = ok ? 1 : 0;
    }
    resp = flowd_objects_json(NULL);
    flowd_response_set_ok(resp, ok);
    json_object_object_add(resp, "saved", json_object_new_int(saved));
    if (!ok)
        json_object_object_add(resp, "error", json_object_new_string("partial_or_failed_save"));
    return resp;
}

struct json_object *flowd_object_delete(struct json_object *body)
{
    sqlite3_stmt *st;
    const char *id = flowd_json_str(body, "id", "");
    int ok = 0;
    struct json_object *resp;
    struct json_object *references = NULL;
    int reference_count = 0;
    int exists = 0;

    if (!flowd_id_ok(id))
        return flowd_error("invalid_id", "invalid flowd object id");
    if (flowd_exec(g_flowd_config_db, "BEGIN IMMEDIATE") != 0)
        return flowd_error("storage_error", "could not lock flowd object store");
    st = flowd_config_prepare("SELECT 1 FROM flowd_objects WHERE id=?1");
    if (st) {
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        exists = sqlite3_step(st) == SQLITE_ROW;
        sqlite3_finalize(st);
    }
    if (!exists) {
        flowd_exec(g_flowd_config_db, "ROLLBACK");
        resp = flowd_error("not_found", "flowd object was not found");
        json_object_object_add(resp, "object_id", json_object_new_string(id));
        json_object_object_add(resp, "http_status", json_object_new_int(404));
        return resp;
    }
    references = flowd_object_references_json(id, &reference_count);
    if (reference_count > 0) {
        flowd_exec(g_flowd_config_db, "ROLLBACK");
        resp = flowd_error("reference_conflict",
                           "flowd object is referenced by active configuration records");
        json_object_object_add(resp, "object_id", json_object_new_string(id));
        json_object_object_add(resp, "reference_count", json_object_new_int(reference_count));
        json_object_object_add(resp, "references", references);
        json_object_object_add(resp, "delete_locked", json_object_new_boolean(1));
        json_object_object_add(resp, "http_status", json_object_new_int(409));
        return resp;
    }
    json_object_put(references);
    st = flowd_config_prepare("DELETE FROM flowd_objects WHERE id=?1");
    if (st) {
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        ok = sqlite3_step(st) == SQLITE_DONE && sqlite3_changes(g_flowd_config_db) > 0;
        sqlite3_finalize(st);
    }
    if (flowd_exec(g_flowd_config_db, ok ? "COMMIT" : "ROLLBACK") != 0)
        ok = 0;
    resp = flowd_objects_json(NULL);
    flowd_response_set_ok(resp, ok);
    json_object_object_add(resp, "deleted", json_object_new_boolean(ok));
    if (!ok)
        json_object_object_add(resp, "error", json_object_new_string("storage_error"));
    return resp;
}

static void flowd_objects_compile_json(struct json_object *out)
{
    sqlite3_stmt *st;
    struct json_object *compiled = json_object_new_array();
    int enabled_count = 0;

    st = flowd_config_prepare(
        "SELECT id,type,name,enabled,value_json,remark,updated_at FROM flowd_objects "
        "WHERE enabled=1 ORDER BY type,id");
    if (st) {
        while (sqlite3_step(st) == SQLITE_ROW) {
            const char *id = (const char *)sqlite3_column_text(st, 0);
            const char *type = (const char *)sqlite3_column_text(st, 1);
            const char *value_s = (const char *)sqlite3_column_text(st, 4);
            struct json_object *value = flowd_json_parse_or_value(value_s);
            struct json_object *o = json_object_new_object();

            json_object_object_add(o, "id", json_object_new_string(id ? id : ""));
            json_object_object_add(o, "type", json_object_new_string(type ? type : ""));
            json_object_object_add(o, "name", flowd_sqlite_text_json(st, 2));
            json_object_object_add(o, "runtime_kind", json_object_new_string(type ? flowd_object_runtime_kind(type) : "object_set"));
            json_object_object_add(o, "artifact", json_object_new_string(id ? id : ""));
            json_object_object_add(o, "value_count", json_object_new_int(flowd_json_value_count(value)));
            json_object_object_add(o, "state", json_object_new_string("planned"));
            json_object_object_add(o, "mutates_dataplane", json_object_new_boolean(0));
            json_object_array_add(compiled, o);
            json_object_put(value);
            enabled_count++;
        }
        sqlite3_finalize(st);
    }
    json_object_object_add(out, "total", json_object_new_int(flowd_count_sql("SELECT COUNT(*) FROM flowd_objects")));
    json_object_object_add(out, "enabled", json_object_new_int(enabled_count));
    json_object_object_add(out, "compiled", compiled);
}

static int flowd_route_mode_ok(const char *mode)
{
    return mode && (!strcmp(mode, "weighted") || !strcmp(mode, "primary_backup") ||
                    !strcmp(mode, "pcc") || !strcmp(mode, "failover") ||
                    !strcmp(mode, "fixed"));
}

static int flowd_route_role_ok(const char *role)
{
    return role && (!strcmp(role, "active") || !strcmp(role, "backup") ||
                    !strcmp(role, "disabled"));
}

static int flowd_route_hash_ok(const char *hash)
{
    char buf[256];
    char *p, *save = NULL;

    if (!hash || !hash[0])
        return 1;
    if (!flowd_text_ok(hash, 192))
        return 0;
    snprintf(buf, sizeof(buf), "%s", hash);
    for (p = strtok_r(buf, ", ", &save); p; p = strtok_r(NULL, ", ", &save)) {
        if (strcmp(p, "src_ip") && strcmp(p, "dst_ip") && strcmp(p, "src_port") &&
            strcmp(p, "dst_port") && strcmp(p, "proto"))
            return 0;
    }
    return 1;
}

static void flowd_route_group_members_json(const char *group_id, struct json_object *members)
{
    sqlite3_stmt *st;

    if (!flowd_id_ok(group_id) || !members)
        return;
    st = flowd_config_prepare(
        "SELECT id,target,weight,role,priority,meta_json,sort_order FROM flowd_route_group_members "
        "WHERE group_id=?1 ORDER BY sort_order,id");
    if (st) {
        sqlite3_bind_text(st, 1, group_id, -1, SQLITE_TRANSIENT);
        while (sqlite3_step(st) == SQLITE_ROW) {
            const char *meta_s = (const char *)sqlite3_column_text(st, 5);
            struct json_object *m = json_object_new_object();

            json_object_object_add(m, "id", flowd_sqlite_text_json(st, 0));
            json_object_object_add(m, "target", flowd_sqlite_text_json(st, 1));
            json_object_object_add(m, "weight", json_object_new_int(sqlite3_column_int(st, 2)));
            json_object_object_add(m, "role", flowd_sqlite_text_json(st, 3));
            json_object_object_add(m, "priority", json_object_new_int(sqlite3_column_int(st, 4)));
            json_object_object_add(m, "meta", flowd_json_parse_or_object(meta_s));
            json_object_object_add(m, "sort_order", json_object_new_int(sqlite3_column_int(st, 6)));
            json_object_array_add(members, m);
        }
        sqlite3_finalize(st);
    }
}

static void flowd_route_group_row_json(struct json_object *arr, sqlite3_stmt *st, int include_members)
{
    const char *id = (const char *)sqlite3_column_text(st, 0);
    struct json_object *o = json_object_new_object();

    json_object_object_add(o, "id", json_object_new_string(id ? id : ""));
    json_object_object_add(o, "name", flowd_sqlite_text_json(st, 1));
    json_object_object_add(o, "enabled", json_object_new_boolean(sqlite3_column_int(st, 2)));
    json_object_object_add(o, "mode", flowd_sqlite_text_json(st, 3));
    json_object_object_add(o, "hash", flowd_sqlite_text_json(st, 4));
    json_object_object_add(o, "health_check", json_object_new_boolean(sqlite3_column_int(st, 5)));
    json_object_object_add(o, "failback", json_object_new_boolean(sqlite3_column_int(st, 6)));
    json_object_object_add(o, "remark", flowd_sqlite_text_json(st, 7));
    json_object_object_add(o, "updated_at", json_object_new_int64(sqlite3_column_int64(st, 8)));
    if (include_members) {
        struct json_object *members = json_object_new_array();
        flowd_route_group_members_json(id, members);
        json_object_object_add(o, "members", members);
    }
    json_object_array_add(arr, o);
}

static int flowd_route_group_members_validate(struct json_object *members)
{
    int i, n;

    if (!members)
        return 0;
    if (!json_object_is_type(members, json_type_array))
        return -1;
    n = json_object_array_length(members);
    for (i = 0; i < n; i++) {
        struct json_object *m = json_object_array_get_idx(members, i);
        struct json_object *meta = NULL;
        const char *id, *target, *role;
        int weight, priority;

        if (!m || !json_object_is_type(m, json_type_object))
            return -1;
        id = flowd_json_str(m, "id", "");
        target = flowd_json_str(m, "target", "");
        role = flowd_json_str(m, "role", "active");
        weight = flowd_json_int(m, "weight", 100);
        priority = flowd_json_int(m, "priority", 100);
        if ((id[0] && !flowd_id_ok(id)) || !flowd_token_ok(target, 128) ||
            !flowd_route_role_ok(role) || weight < 0 || weight > 100000 ||
            priority < 0 || priority > 100000)
            return -1;
        if (json_object_object_get_ex(m, "meta", &meta) && meta &&
            !flowd_json_fits(meta, FLOWD_MAX_JSON))
            return -1;
    }
    return 0;
}

struct json_object *flowd_route_groups_json(struct json_object *body)
{
    sqlite3_stmt *st = NULL;
    struct json_object *resp = json_object_new_object();
    struct json_object *arr = json_object_new_array();
    const char *id = flowd_json_str(body, "id", "");
    int include_disabled = flowd_json_bool(body, "include_disabled", 1);
    int include_members = flowd_json_bool(body, "include_members", 1);
    int ok = 1;
    int rc;
    const char *error = "";

    if (id && id[0] && !flowd_id_ok(id))
        return flowd_error("invalid_id", "invalid flowd route group id");
    if (id && id[0]) {
        st = flowd_config_prepare(
            "SELECT id,name,enabled,mode,hash,health_check,failback,remark,updated_at "
            "FROM flowd_route_groups WHERE id=?1");
        if (st)
            sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    } else {
        st = flowd_config_prepare(
            "SELECT id,name,enabled,mode,hash,health_check,failback,remark,updated_at "
            "FROM flowd_route_groups WHERE (?1 OR enabled=1) ORDER BY id");
        if (st)
            sqlite3_bind_int(st, 1, include_disabled ? 1 : 0);
    }
    if (st) {
        while ((rc = sqlite3_step(st)) == SQLITE_ROW)
            flowd_route_group_row_json(arr, st, include_members);
        if (rc != SQLITE_DONE) {
            ok = 0;
            error = "route_groups_unavailable";
            fprintf(stderr, "[dreamingwrt-flowd] route groups query failed: %s\n",
                    g_flowd_config_db ? sqlite3_errmsg(g_flowd_config_db) : "database unavailable");
        }
        sqlite3_finalize(st);
    } else {
        ok = 0;
        error = "route_groups_unavailable";
    }
    flowd_list_total_add(resp, &ok, &error, "SELECT COUNT(*) FROM flowd_route_groups",
                         "route_groups_count_unavailable");
    json_object_object_add(resp, "ok", json_object_new_boolean(ok));
    json_object_object_add(resp, "groups", arr);
    if (error[0])
        json_object_object_add(resp, "error", json_object_new_string(error));
    return resp;
}

static int flowd_route_group_members_save(const char *group_id, struct json_object *members)
{
    sqlite3_stmt *st;
    int i, n;

    if (!flowd_id_ok(group_id))
        return -1;
    if (flowd_route_group_members_validate(members) != 0)
        return -1;
    if (!members)
        return 0;
    st = flowd_config_prepare("DELETE FROM flowd_route_group_members WHERE group_id=?1");
    if (!st)
        return -1;
    sqlite3_bind_text(st, 1, group_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_DONE) {
        sqlite3_finalize(st);
        return -1;
    }
    sqlite3_finalize(st);
    n = json_object_array_length(members);
    for (i = 0; i < n; i++) {
        struct json_object *m = json_object_array_get_idx(members, i);
        struct json_object *meta = NULL;
        char generated_id[FLOWD_MAX_ID];
        const char *id, *target, *role, *meta_s = "{}";
        int weight, priority;

        if (!m || !json_object_is_type(m, json_type_object))
            return -1;
        id = flowd_json_str(m, "id", "");
        if (!id[0]) {
            flowd_make_id("route-member", generated_id, sizeof(generated_id));
            id = generated_id;
        }
        target = flowd_json_str(m, "target", "");
        role = flowd_json_str(m, "role", "active");
        weight = flowd_json_int(m, "weight", 100);
        priority = flowd_json_int(m, "priority", 100);
        if (!flowd_id_ok(id) || !flowd_token_ok(target, 128) || !flowd_route_role_ok(role) ||
            weight < 0 || weight > 100000 || priority < 0 || priority > 100000)
            return -1;
        if (json_object_object_get_ex(m, "meta", &meta) && meta) {
            if (!flowd_json_fits(meta, FLOWD_MAX_JSON))
                return -1;
            meta_s = json_object_to_json_string_ext(meta, JSON_C_TO_STRING_PLAIN);
        }
        st = flowd_config_prepare(
            "INSERT INTO flowd_route_group_members"
            "(id,group_id,target,weight,role,priority,meta_json,sort_order) "
            "VALUES(?1,?2,?3,?4,?5,?6,?7,?8)");
        if (!st)
            return -1;
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, group_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 3, target, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 4, weight);
        sqlite3_bind_text(st, 5, role, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 6, priority);
        sqlite3_bind_text(st, 7, meta_s, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 8, i);
        if (sqlite3_step(st) != SQLITE_DONE) {
            sqlite3_finalize(st);
            return -1;
        }
        sqlite3_finalize(st);
    }
    return 0;
}

static int flowd_route_group_load_existing(const char *id, char *name, size_t name_len,
                                           int *enabled, char *mode, size_t mode_len,
                                           char *hash, size_t hash_len,
                                           int *health_check, int *failback,
                                           char *remark, size_t remark_len)
{
    sqlite3_stmt *st;
    int rc;

    if (!flowd_id_ok(id))
        return -1;
    st = flowd_config_prepare(
        "SELECT name,enabled,mode,hash,health_check,failback,remark "
        "FROM flowd_route_groups WHERE id=?1");
    if (!st)
        return -1;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) {
        snprintf(name, name_len, "%s",
                 sqlite3_column_text(st, 0) ? (const char *)sqlite3_column_text(st, 0) : "");
        if (enabled)
            *enabled = sqlite3_column_int(st, 1) ? 1 : 0;
        snprintf(mode, mode_len, "%s",
                 sqlite3_column_text(st, 2) ? (const char *)sqlite3_column_text(st, 2) : "weighted");
        snprintf(hash, hash_len, "%s",
                 sqlite3_column_text(st, 3) ? (const char *)sqlite3_column_text(st, 3) : "src_ip,dst_ip,dst_port");
        if (health_check)
            *health_check = sqlite3_column_int(st, 4) ? 1 : 0;
        if (failback)
            *failback = sqlite3_column_int(st, 5) ? 1 : 0;
        snprintf(remark, remark_len, "%s",
                 sqlite3_column_text(st, 6) ? (const char *)sqlite3_column_text(st, 6) : "");
        sqlite3_finalize(st);
        return 1;
    }
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

static int flowd_route_group_save_one(struct json_object *body)
{
    sqlite3_stmt *st;
    struct json_object *members = NULL;
    char generated_id[FLOWD_MAX_ID];
    char name_buf[129] = "";
    char mode_buf[32] = "weighted";
    char hash_buf[193] = "src_ip,dst_ip,dst_port";
    char remark_buf[257] = "";
    const char *id, *name, *mode, *hash, *remark;
    int enabled, health_check, failback, ok = 0;
    int64_t now = flowd_now_s();

    if (!body || !json_object_is_type(body, json_type_object))
        return -1;
    enabled = 1;
    health_check = 1;
    failback = 1;
    id = flowd_json_str(body, "id", "");
    if (!id[0]) {
        flowd_make_id("route-group", generated_id, sizeof(generated_id));
        id = generated_id;
    } else {
        int existing;
        existing = flowd_route_group_load_existing(id, name_buf, sizeof(name_buf),
                                                   &enabled, mode_buf, sizeof(mode_buf),
                                                   hash_buf, sizeof(hash_buf),
                                                   &health_check, &failback,
                                                   remark_buf, sizeof(remark_buf));
        if (existing < 0)
            return -1;
    }
    name = flowd_json_str(body, "name", name_buf);
    mode = flowd_json_str(body, "mode", mode_buf);
    hash = flowd_json_str(body, "hash", hash_buf);
    remark = flowd_json_str(body, "remark", remark_buf);
    enabled = flowd_json_bool(body, "enabled", enabled);
    health_check = flowd_json_bool(body, "health_check", health_check);
    failback = flowd_json_bool(body, "failback", failback);
    json_object_object_get_ex(body, "members", &members);
    if (!flowd_id_ok(id) || !flowd_text_ok(name, 128) || !flowd_route_mode_ok(mode) ||
        !flowd_route_hash_ok(hash) || !flowd_text_ok(remark, 256))
        return -1;
    if (members && flowd_route_group_members_validate(members) != 0)
        return -1;
    if (flowd_exec(g_flowd_config_db, "BEGIN IMMEDIATE") != 0)
        return -1;
    st = flowd_config_prepare(
        "INSERT INTO flowd_route_groups"
        "(id,name,enabled,mode,hash,health_check,failback,remark,created_at,updated_at) "
        "VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?9) "
        "ON CONFLICT(id) DO UPDATE SET name=excluded.name,enabled=excluded.enabled,"
        "mode=excluded.mode,hash=excluded.hash,health_check=excluded.health_check,"
        "failback=excluded.failback,remark=excluded.remark,updated_at=excluded.updated_at");
    if (st) {
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, name, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 3, enabled ? 1 : 0);
        sqlite3_bind_text(st, 4, mode, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 5, hash, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 6, health_check ? 1 : 0);
        sqlite3_bind_int(st, 7, failback ? 1 : 0);
        sqlite3_bind_text(st, 8, remark, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 9, now);
        ok = sqlite3_step(st) == SQLITE_DONE;
        sqlite3_finalize(st);
    }
    if (!ok || (members && flowd_route_group_members_save(id, members) != 0)) {
        flowd_exec(g_flowd_config_db, "ROLLBACK");
        return -1;
    }
    if (flowd_exec(g_flowd_config_db, "COMMIT") != 0) {
        flowd_exec(g_flowd_config_db, "ROLLBACK");
        return -1;
    }
    return 0;
}

struct json_object *flowd_route_group_update(struct json_object *body)
{
    struct json_object *arr = NULL;
    int ok = 1, saved = 0, i, n;
    struct json_object *resp;

    if (!body || !json_object_is_type(body, json_type_object))
        return flowd_error("invalid_request", "route group body must be an object");
    if (json_object_object_get_ex(body, "groups", &arr) && arr &&
        json_object_is_type(arr, json_type_array)) {
        n = json_object_array_length(arr);
        for (i = 0; i < n; i++) {
            if (flowd_route_group_save_one(json_object_array_get_idx(arr, i)) == 0)
                saved++;
            else
                ok = 0;
        }
    } else {
        ok = flowd_route_group_save_one(body) == 0;
        saved = ok ? 1 : 0;
    }
    resp = flowd_route_groups_json(NULL);
    flowd_response_set_ok(resp, ok);
    json_object_object_add(resp, "saved", json_object_new_int(saved));
    if (!ok)
        json_object_object_add(resp, "error", json_object_new_string("partial_or_failed_save"));
    return resp;
}

struct json_object *flowd_route_group_delete(struct json_object *body)
{
    sqlite3_stmt *st;
    const char *id = flowd_json_str(body, "id", "");
    int ok = 0;
    struct json_object *resp;

    if (!flowd_id_ok(id))
        return flowd_error("invalid_id", "invalid flowd route group id");
    st = flowd_config_prepare("DELETE FROM flowd_route_groups WHERE id=?1");
    if (st) {
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        ok = sqlite3_step(st) == SQLITE_DONE && sqlite3_changes(g_flowd_config_db) > 0;
        sqlite3_finalize(st);
    }
    resp = flowd_route_groups_json(NULL);
    flowd_response_set_ok(resp, ok);
    json_object_object_add(resp, "deleted", json_object_new_boolean(ok));
    if (!ok)
        json_object_object_add(resp, "error", json_object_new_string("not_found"));
    return resp;
}

static void flowd_route_groups_compile_json(struct json_object *out)
{
    sqlite3_stmt *st;
    struct json_object *compiled = json_object_new_array();
    int enabled_count = 0;

    st = flowd_config_prepare(
        "SELECT id,name,enabled,mode,hash,health_check,failback,remark,updated_at "
        "FROM flowd_route_groups WHERE enabled=1 ORDER BY id");
    if (st) {
        while (sqlite3_step(st) == SQLITE_ROW) {
            const char *id = (const char *)sqlite3_column_text(st, 0);
            struct json_object *o = json_object_new_object();
            struct json_object *members = json_object_new_array();

            flowd_route_group_members_json(id, members);
            json_object_object_add(o, "id", json_object_new_string(id ? id : ""));
            json_object_object_add(o, "name", flowd_sqlite_text_json(st, 1));
            json_object_object_add(o, "mode", flowd_sqlite_text_json(st, 3));
            json_object_object_add(o, "hash", flowd_sqlite_text_json(st, 4));
            json_object_object_add(o, "health_check", json_object_new_boolean(sqlite3_column_int(st, 5)));
            json_object_object_add(o, "failback", json_object_new_boolean(sqlite3_column_int(st, 6)));
            json_object_object_add(o, "members", members);
            json_object_object_add(o, "member_count", json_object_new_int(json_object_array_length(members)));
            json_object_object_add(o, "runtime_kind", json_object_new_string("fwmark_route_group"));
            json_object_object_add(o, "state", json_object_new_string("planned"));
            json_object_object_add(o, "mutates_dataplane", json_object_new_boolean(0));
            json_object_array_add(compiled, o);
            enabled_count++;
        }
        sqlite3_finalize(st);
    }
    json_object_object_add(out, "total", json_object_new_int(flowd_count_sql("SELECT COUNT(*) FROM flowd_route_groups")));
    json_object_object_add(out, "enabled", json_object_new_int(enabled_count));
    json_object_object_add(out, "compiled", compiled);
}

static int flowd_wan_capacity_scheduler_ok(const char *scheduler)
{
    return scheduler && (!strcmp(scheduler, "cake") || !strcmp(scheduler, "fq_codel") ||
                         !strcmp(scheduler, "htb") || !strcmp(scheduler, "none"));
}

static int flowd_wan_capacity_link_layer_ok(const char *link_layer)
{
    return link_layer && (!strcmp(link_layer, "ethernet") ||
                          !strcmp(link_layer, "atm") ||
                          !strcmp(link_layer, "ptm") ||
                          !strcmp(link_layer, "none"));
}

static void flowd_wan_capacity_row_json(struct json_object *arr, sqlite3_stmt *st)
{
    struct json_object *o = json_object_new_object();

    json_object_object_add(o, "id", flowd_sqlite_text_json(st, 0));
    json_object_object_add(o, "name", flowd_sqlite_text_json(st, 1));
    json_object_object_add(o, "enabled", json_object_new_boolean(sqlite3_column_int(st, 2)));
    json_object_object_add(o, "wan", flowd_sqlite_text_json(st, 3));
    json_object_object_add(o, "down_kbps", json_object_new_int(sqlite3_column_int(st, 4)));
    json_object_object_add(o, "up_kbps", json_object_new_int(sqlite3_column_int(st, 5)));
    json_object_object_add(o, "headroom_pct", json_object_new_int(sqlite3_column_int(st, 6)));
    json_object_object_add(o, "scheduler", flowd_sqlite_text_json(st, 7));
    json_object_object_add(o, "link_layer", flowd_sqlite_text_json(st, 8));
    json_object_object_add(o, "overhead_bytes", json_object_new_int(sqlite3_column_int(st, 9)));
    json_object_object_add(o, "ingress", json_object_new_boolean(sqlite3_column_int(st, 10)));
    json_object_object_add(o, "egress", json_object_new_boolean(sqlite3_column_int(st, 11)));
    json_object_object_add(o, "source", flowd_sqlite_text_json(st, 12));
    json_object_object_add(o, "remark", flowd_sqlite_text_json(st, 13));
    json_object_object_add(o, "updated_at", json_object_new_int64(sqlite3_column_int64(st, 14)));
    json_object_array_add(arr, o);
}

static int flowd_wan_capacity_id_for_wan(const char *wan, char *out, size_t out_len)
{
    sqlite3_stmt *st;
    const char *id;
    int found = 0;

    if (!flowd_token_ok(wan, 128) || !out || out_len == 0)
        return 0;
    st = flowd_config_prepare("SELECT id FROM flowd_wan_capacity WHERE wan=?1 LIMIT 1");
    if (!st)
        return 0;
    sqlite3_bind_text(st, 1, wan, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW) {
        id = (const char *)sqlite3_column_text(st, 0);
        if (id && id[0]) {
            snprintf(out, out_len, "%s", id);
            found = 1;
        }
    }
    sqlite3_finalize(st);
    return found;
}

static int flowd_wan_capacity_load_existing(const char *id, char *name, size_t name_len,
                                            int *enabled, char *wan, size_t wan_len,
                                            int *down_kbps, int *up_kbps, int *headroom_pct,
                                            char *scheduler, size_t scheduler_len,
                                            char *link_layer, size_t link_layer_len,
                                            int *overhead_bytes, int *ingress, int *egress,
                                            char *source, size_t source_len,
                                            char *remark, size_t remark_len)
{
    sqlite3_stmt *st;
    int rc;

    if (!flowd_id_ok(id))
        return -1;
    st = flowd_config_prepare(
        "SELECT name,enabled,wan,down_kbps,up_kbps,headroom_pct,scheduler,link_layer,"
        "overhead_bytes,ingress,egress,source,remark FROM flowd_wan_capacity WHERE id=?1");
    if (!st)
        return -1;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) {
        snprintf(name, name_len, "%s",
                 sqlite3_column_text(st, 0) ? (const char *)sqlite3_column_text(st, 0) : "");
        if (enabled)
            *enabled = sqlite3_column_int(st, 1) ? 1 : 0;
        snprintf(wan, wan_len, "%s",
                 sqlite3_column_text(st, 2) ? (const char *)sqlite3_column_text(st, 2) : "");
        if (down_kbps)
            *down_kbps = sqlite3_column_int(st, 3);
        if (up_kbps)
            *up_kbps = sqlite3_column_int(st, 4);
        if (headroom_pct)
            *headroom_pct = sqlite3_column_int(st, 5);
        snprintf(scheduler, scheduler_len, "%s",
                 sqlite3_column_text(st, 6) ? (const char *)sqlite3_column_text(st, 6) : "cake");
        snprintf(link_layer, link_layer_len, "%s",
                 sqlite3_column_text(st, 7) ? (const char *)sqlite3_column_text(st, 7) : "ethernet");
        if (overhead_bytes)
            *overhead_bytes = sqlite3_column_int(st, 8);
        if (ingress)
            *ingress = sqlite3_column_int(st, 9) ? 1 : 0;
        if (egress)
            *egress = sqlite3_column_int(st, 10) ? 1 : 0;
        snprintf(source, source_len, "%s",
                 sqlite3_column_text(st, 11) ? (const char *)sqlite3_column_text(st, 11) : "manual");
        snprintf(remark, remark_len, "%s",
                 sqlite3_column_text(st, 12) ? (const char *)sqlite3_column_text(st, 12) : "");
        sqlite3_finalize(st);
        return 1;
    }
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

struct json_object *flowd_wan_capacity_json(struct json_object *body)
{
    sqlite3_stmt *st = NULL;
    struct json_object *resp = json_object_new_object();
    struct json_object *arr = json_object_new_array();
    const char *id = flowd_json_str(body, "id", "");
    const char *wan = flowd_json_str(body, "wan", "");
    int include_disabled = flowd_json_bool(body, "include_disabled", 1);
    int ok = 1;
    const char *error = "";

    if (id && id[0] && !flowd_id_ok(id))
        return flowd_error("invalid_id", "invalid wan capacity id");
    if (wan && wan[0] && !flowd_token_ok(wan, 128))
        return flowd_error("invalid_wan", "invalid wan id");
    if (id && id[0]) {
        st = flowd_config_prepare(
            "SELECT id,name,enabled,wan,down_kbps,up_kbps,headroom_pct,scheduler,link_layer,"
            "overhead_bytes,ingress,egress,source,remark,updated_at "
            "FROM flowd_wan_capacity WHERE id=?1");
        if (st)
            sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    } else if (wan && wan[0]) {
        st = flowd_config_prepare(
            "SELECT id,name,enabled,wan,down_kbps,up_kbps,headroom_pct,scheduler,link_layer,"
            "overhead_bytes,ingress,egress,source,remark,updated_at "
            "FROM flowd_wan_capacity WHERE wan=?1 AND (?2 OR enabled=1) ORDER BY id");
        if (st) {
            sqlite3_bind_text(st, 1, wan, -1, SQLITE_TRANSIENT);
            sqlite3_bind_int(st, 2, include_disabled ? 1 : 0);
        }
    } else {
        st = flowd_config_prepare(
            "SELECT id,name,enabled,wan,down_kbps,up_kbps,headroom_pct,scheduler,link_layer,"
            "overhead_bytes,ingress,egress,source,remark,updated_at "
            "FROM flowd_wan_capacity WHERE (?1 OR enabled=1) ORDER BY wan,id");
        if (st)
            sqlite3_bind_int(st, 1, include_disabled ? 1 : 0);
    }
    if (st) {
        ok = flowd_collect_rows(st, arr, flowd_wan_capacity_row_json, "wan capacity");
        if (!ok)
            error = "wan_capacity_unavailable";
        sqlite3_finalize(st);
    } else {
        ok = 0;
        error = "wan_capacity_unavailable";
    }
    flowd_list_total_add(resp, &ok, &error, "SELECT COUNT(*) FROM flowd_wan_capacity",
                         "wan_capacity_count_unavailable");
    json_object_object_add(resp, "ok", json_object_new_boolean(ok));
    json_object_object_add(resp, "entries", arr);
    if (error[0])
        json_object_object_add(resp, "error", json_object_new_string(error));
    return resp;
}

static int flowd_wan_capacity_save_one(struct json_object *body)
{
    sqlite3_stmt *st;
    char generated_id[FLOWD_MAX_ID];
    char name_buf[129] = "";
    char wan_buf[129] = "";
    char scheduler_buf[32] = "cake";
    char link_layer_buf[32] = "ethernet";
    char source_buf[65] = "manual";
    char remark_buf[257] = "";
    const char *id, *name, *wan, *scheduler, *link_layer, *source, *remark;
    int enabled, down_kbps, up_kbps, headroom_pct, overhead_bytes, ingress, egress, ok = 0;
    int load_existing = 0;
    int64_t now = flowd_now_s();

    if (!body || !json_object_is_type(body, json_type_object))
        return -1;
    id = flowd_json_str(body, "id", "");
    name = flowd_json_str(body, "name", "");
    enabled = flowd_json_bool(body, "enabled", 1);
    wan = flowd_json_str(body, "wan", "");
    if (id[0]) {
        load_existing = 1;
    } else {
        if (flowd_wan_capacity_id_for_wan(wan, generated_id, sizeof(generated_id))) {
            load_existing = 1;
        } else {
            flowd_make_id("wan-capacity", generated_id, sizeof(generated_id));
        }
        id = generated_id;
    }
    snprintf(name_buf, sizeof(name_buf), "%s", name);
    snprintf(wan_buf, sizeof(wan_buf), "%s", wan);
    enabled = enabled ? 1 : 0;
    down_kbps = 0;
    up_kbps = 0;
    headroom_pct = 95;
    overhead_bytes = 0;
    ingress = 1;
    egress = 1;
    if (load_existing) {
        int existing = flowd_wan_capacity_load_existing(id, name_buf, sizeof(name_buf),
                                                        &enabled, wan_buf, sizeof(wan_buf),
                                                        &down_kbps, &up_kbps, &headroom_pct,
                                                        scheduler_buf, sizeof(scheduler_buf),
                                                        link_layer_buf, sizeof(link_layer_buf),
                                                        &overhead_bytes, &ingress, &egress,
                                                        source_buf, sizeof(source_buf),
                                                        remark_buf, sizeof(remark_buf));
        if (existing < 0)
            return -1;
    }
    name = flowd_json_str(body, "name", name_buf);
    enabled = flowd_json_bool(body, "enabled", enabled);
    wan = flowd_json_str(body, "wan", wan_buf);
    down_kbps = flowd_json_int(body, "down_kbps", down_kbps);
    up_kbps = flowd_json_int(body, "up_kbps", up_kbps);
    headroom_pct = flowd_json_int(body, "headroom_pct", headroom_pct);
    scheduler = flowd_json_str(body, "scheduler", scheduler_buf);
    link_layer = flowd_json_str(body, "link_layer", link_layer_buf);
    overhead_bytes = flowd_json_int(body, "overhead_bytes", overhead_bytes);
    ingress = flowd_json_bool(body, "ingress", ingress);
    egress = flowd_json_bool(body, "egress", egress);
    source = flowd_json_str(body, "source", source_buf);
    remark = flowd_json_str(body, "remark", remark_buf);
    if (!flowd_id_ok(id) || !flowd_text_ok(name, 128) || !flowd_token_ok(wan, 128) ||
        down_kbps < 0 || down_kbps > 100000000 || up_kbps < 0 || up_kbps > 100000000 ||
        headroom_pct < 50 || headroom_pct > 100 ||
        !flowd_wan_capacity_scheduler_ok(scheduler) ||
        !flowd_wan_capacity_link_layer_ok(link_layer) ||
        overhead_bytes < -128 || overhead_bytes > 512 ||
        !flowd_token_ok(source, 64) || !flowd_text_ok(remark, 256))
        return -1;
    st = flowd_config_prepare(
        "INSERT INTO flowd_wan_capacity"
        "(id,name,enabled,wan,down_kbps,up_kbps,headroom_pct,scheduler,link_layer,overhead_bytes,"
        "ingress,egress,source,remark,created_at,updated_at) "
        "VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?15) "
        "ON CONFLICT(id) DO UPDATE SET name=excluded.name,enabled=excluded.enabled,wan=excluded.wan,"
        "down_kbps=excluded.down_kbps,up_kbps=excluded.up_kbps,headroom_pct=excluded.headroom_pct,"
        "scheduler=excluded.scheduler,link_layer=excluded.link_layer,overhead_bytes=excluded.overhead_bytes,"
        "ingress=excluded.ingress,egress=excluded.egress,source=excluded.source,remark=excluded.remark,"
        "updated_at=excluded.updated_at");
    if (st) {
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, name, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 3, enabled ? 1 : 0);
        sqlite3_bind_text(st, 4, wan, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 5, down_kbps);
        sqlite3_bind_int(st, 6, up_kbps);
        sqlite3_bind_int(st, 7, headroom_pct);
        sqlite3_bind_text(st, 8, scheduler, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 9, link_layer, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 10, overhead_bytes);
        sqlite3_bind_int(st, 11, ingress ? 1 : 0);
        sqlite3_bind_int(st, 12, egress ? 1 : 0);
        sqlite3_bind_text(st, 13, source, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 14, remark, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 15, now);
        ok = sqlite3_step(st) == SQLITE_DONE;
        sqlite3_finalize(st);
    }
    return ok ? 0 : -1;
}

struct json_object *flowd_wan_capacity_update(struct json_object *body)
{
    struct json_object *arr = NULL;
    int ok = 1, saved = 0, i, n;
    struct json_object *resp;

    if (!body || !json_object_is_type(body, json_type_object))
        return flowd_error("invalid_request", "wan capacity body must be an object");
    if (json_object_object_get_ex(body, "entries", &arr) && arr &&
        json_object_is_type(arr, json_type_array)) {
        n = json_object_array_length(arr);
        for (i = 0; i < n; i++) {
            if (flowd_wan_capacity_save_one(json_object_array_get_idx(arr, i)) == 0)
                saved++;
            else
                ok = 0;
        }
    } else {
        ok = flowd_wan_capacity_save_one(body) == 0;
        saved = ok ? 1 : 0;
    }
    resp = flowd_wan_capacity_json(NULL);
    flowd_response_set_ok(resp, ok);
    json_object_object_add(resp, "saved", json_object_new_int(saved));
    if (!ok)
        json_object_object_add(resp, "error", json_object_new_string("partial_or_failed_save"));
    return resp;
}

struct json_object *flowd_wan_capacity_delete(struct json_object *body)
{
    sqlite3_stmt *st;
    const char *id = flowd_json_str(body, "id", "");
    int ok = 0;
    struct json_object *resp;

    if (!flowd_id_ok(id))
        return flowd_error("invalid_id", "invalid wan capacity id");
    st = flowd_config_prepare("DELETE FROM flowd_wan_capacity WHERE id=?1");
    if (st) {
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        ok = sqlite3_step(st) == SQLITE_DONE && sqlite3_changes(g_flowd_config_db) > 0;
        sqlite3_finalize(st);
    }
    resp = flowd_wan_capacity_json(NULL);
    flowd_response_set_ok(resp, ok);
    json_object_object_add(resp, "deleted", json_object_new_boolean(ok));
    if (!ok)
        json_object_object_add(resp, "error", json_object_new_string("not_found"));
    return resp;
}

static void flowd_wan_capacity_compile_json(struct json_object *out)
{
    sqlite3_stmt *st;
    struct json_object *entries = json_object_new_array();
    int enabled_count = 0;

    st = flowd_config_prepare(
        "SELECT id,name,enabled,wan,down_kbps,up_kbps,headroom_pct,scheduler,link_layer,"
        "overhead_bytes,ingress,egress,source,remark,updated_at "
        "FROM flowd_wan_capacity WHERE enabled=1 ORDER BY wan,id");
    if (st) {
        while (sqlite3_step(st) == SQLITE_ROW) {
            struct json_object *o = json_object_new_object();
            int64_t down_kbps = sqlite3_column_int64(st, 4);
            int64_t up_kbps = sqlite3_column_int64(st, 5);
            int headroom_pct = sqlite3_column_int(st, 6);

            json_object_object_add(o, "id", flowd_sqlite_text_json(st, 0));
            json_object_object_add(o, "name", flowd_sqlite_text_json(st, 1));
            json_object_object_add(o, "wan", flowd_sqlite_text_json(st, 3));
            json_object_object_add(o, "down_kbps", json_object_new_int64(down_kbps));
            json_object_object_add(o, "up_kbps", json_object_new_int64(up_kbps));
            json_object_object_add(o, "effective_down_kbps", json_object_new_int64((down_kbps * headroom_pct) / 100));
            json_object_object_add(o, "effective_up_kbps", json_object_new_int64((up_kbps * headroom_pct) / 100));
            json_object_object_add(o, "headroom_pct", json_object_new_int(headroom_pct));
            json_object_object_add(o, "scheduler", flowd_sqlite_text_json(st, 7));
            json_object_object_add(o, "link_layer", flowd_sqlite_text_json(st, 8));
            json_object_object_add(o, "overhead_bytes", json_object_new_int(sqlite3_column_int(st, 9)));
            json_object_object_add(o, "ingress", json_object_new_boolean(sqlite3_column_int(st, 10)));
            json_object_object_add(o, "egress", json_object_new_boolean(sqlite3_column_int(st, 11)));
            json_object_object_add(o, "source", flowd_sqlite_text_json(st, 12));
            json_object_object_add(o, "runtime_kind", json_object_new_string("wan_capacity_profile"));
            json_object_object_add(o, "executor", json_object_new_string("tc_shaper_pending"));
            json_object_object_add(o, "state", json_object_new_string("planned"));
            json_object_object_add(o, "mutates_dataplane", json_object_new_boolean(0));
            json_object_array_add(entries, o);
            enabled_count++;
        }
        sqlite3_finalize(st);
    }
    json_object_object_add(out, "total", json_object_new_int(flowd_count_sql("SELECT COUNT(*) FROM flowd_wan_capacity")));
    json_object_object_add(out, "enabled", json_object_new_int(enabled_count));
    json_object_object_add(out, "entries", entries);
}

static int flowd_wan_health_method_ok(const char *method)
{
    return method && (!strcmp(method, "icmp") || !strcmp(method, "tcp") ||
                      !strcmp(method, "dns") || !strcmp(method, "http") ||
                      !strcmp(method, "https"));
}

static struct json_object *flowd_wan_health_targets_from_body(struct json_object *body)
{
    struct json_object *v = NULL;
    struct json_object *parsed = NULL;

    if (!body || !json_object_is_type(body, json_type_object))
        return json_object_new_array();
    if (!json_object_object_get_ex(body, "targets", &v) &&
        !json_object_object_get_ex(body, "targets_json", &v))
        return json_object_new_array();
    if (!v)
        return json_object_new_array();
    if (json_object_is_type(v, json_type_string)) {
        parsed = json_tokener_parse(json_object_get_string(v));
        if (parsed)
            return parsed;
    }
    return json_object_get(v);
}

static int flowd_wan_health_targets_ok(struct json_object *targets)
{
    int i, n;

    if (!targets || !json_object_is_type(targets, json_type_array))
        return 0;
    n = json_object_array_length(targets);
    if (n < 1 || n > 16)
        return 0;
    for (i = 0; i < n; i++) {
        struct json_object *v = json_object_array_get_idx(targets, i);
        const char *s = v ? json_object_get_string(v) : NULL;

        if (!v || !json_object_is_type(v, json_type_string) ||
            !s || !s[0] || !flowd_text_ok(s, 256))
            return 0;
    }
    return flowd_json_fits(targets, FLOWD_MAX_JSON);
}

static int flowd_wan_health_targets_present(struct json_object *body)
{
    struct json_object *v = NULL;

    return body && json_object_is_type(body, json_type_object) &&
           (json_object_object_get_ex(body, "targets", &v) ||
            json_object_object_get_ex(body, "targets_json", &v));
}

static void flowd_wan_health_row_json(struct json_object *arr, sqlite3_stmt *st)
{
    const char *targets_s = (const char *)sqlite3_column_text(st, 5);
    struct json_object *o = json_object_new_object();

    json_object_object_add(o, "id", flowd_sqlite_text_json(st, 0));
    json_object_object_add(o, "name", flowd_sqlite_text_json(st, 1));
    json_object_object_add(o, "enabled", json_object_new_boolean(sqlite3_column_int(st, 2)));
    json_object_object_add(o, "wan", flowd_sqlite_text_json(st, 3));
    json_object_object_add(o, "method", flowd_sqlite_text_json(st, 4));
    json_object_object_add(o, "targets", flowd_json_parse_or_array(targets_s));
    json_object_object_add(o, "interval_s", json_object_new_int(sqlite3_column_int(st, 6)));
    json_object_object_add(o, "timeout_ms", json_object_new_int(sqlite3_column_int(st, 7)));
    json_object_object_add(o, "loss_threshold_pct", json_object_new_int(sqlite3_column_int(st, 8)));
    json_object_object_add(o, "latency_threshold_ms", json_object_new_int(sqlite3_column_int(st, 9)));
    json_object_object_add(o, "fail_count", json_object_new_int(sqlite3_column_int(st, 10)));
    json_object_object_add(o, "recover_count", json_object_new_int(sqlite3_column_int(st, 11)));
    json_object_object_add(o, "remark", flowd_sqlite_text_json(st, 12));
    json_object_object_add(o, "updated_at", json_object_new_int64(sqlite3_column_int64(st, 13)));
    json_object_array_add(arr, o);
}

struct json_object *flowd_wan_health_json(struct json_object *body)
{
    sqlite3_stmt *st = NULL;
    struct json_object *resp = json_object_new_object();
    struct json_object *arr = json_object_new_array();
    const char *id = flowd_json_str(body, "id", "");
    const char *wan = flowd_json_str(body, "wan", "");
    int include_disabled = flowd_json_bool(body, "include_disabled", 1);
    int ok = 1;
    const char *error = "";

    if (id && id[0] && !flowd_id_ok(id))
        return flowd_error("invalid_id", "invalid wan health id");
    if (wan && wan[0] && !flowd_token_ok(wan, 128))
        return flowd_error("invalid_wan", "invalid wan id");
    if (id && id[0]) {
        st = flowd_config_prepare(
            "SELECT id,name,enabled,wan,method,targets_json,interval_s,timeout_ms,"
            "loss_threshold_pct,latency_threshold_ms,fail_count,recover_count,remark,updated_at "
            "FROM flowd_wan_health WHERE id=?1");
        if (st)
            sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    } else if (wan && wan[0]) {
        st = flowd_config_prepare(
            "SELECT id,name,enabled,wan,method,targets_json,interval_s,timeout_ms,"
            "loss_threshold_pct,latency_threshold_ms,fail_count,recover_count,remark,updated_at "
            "FROM flowd_wan_health WHERE wan=?1 AND (?2 OR enabled=1) ORDER BY id");
        if (st) {
            sqlite3_bind_text(st, 1, wan, -1, SQLITE_TRANSIENT);
            sqlite3_bind_int(st, 2, include_disabled ? 1 : 0);
        }
    } else {
        st = flowd_config_prepare(
            "SELECT id,name,enabled,wan,method,targets_json,interval_s,timeout_ms,"
            "loss_threshold_pct,latency_threshold_ms,fail_count,recover_count,remark,updated_at "
            "FROM flowd_wan_health WHERE (?1 OR enabled=1) ORDER BY wan,id");
        if (st)
            sqlite3_bind_int(st, 1, include_disabled ? 1 : 0);
    }
    if (st) {
        ok = flowd_collect_rows(st, arr, flowd_wan_health_row_json, "wan health");
        if (!ok)
            error = "wan_health_unavailable";
        sqlite3_finalize(st);
    } else {
        ok = 0;
        error = "wan_health_unavailable";
    }
    flowd_list_total_add(resp, &ok, &error, "SELECT COUNT(*) FROM flowd_wan_health",
                         "wan_health_count_unavailable");
    json_object_object_add(resp, "ok", json_object_new_boolean(ok));
    json_object_object_add(resp, "checks", arr);
    if (error[0])
        json_object_object_add(resp, "error", json_object_new_string(error));
    return resp;
}

static int flowd_wan_health_load_existing(const char *id, char *name, size_t name_len,
                                          int *enabled, char *wan, size_t wan_len,
                                          char *method, size_t method_len,
                                          struct json_object **targets,
                                          int *interval_s, int *timeout_ms,
                                          int *loss_threshold_pct,
                                          int *latency_threshold_ms,
                                          int *fail_count, int *recover_count,
                                          char *remark, size_t remark_len)
{
    sqlite3_stmt *st;
    int rc;

    if (!flowd_id_ok(id))
        return -1;
    st = flowd_config_prepare(
        "SELECT name,enabled,wan,method,targets_json,interval_s,timeout_ms,"
        "loss_threshold_pct,latency_threshold_ms,fail_count,recover_count,remark "
        "FROM flowd_wan_health WHERE id=?1");
    if (!st)
        return -1;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) {
        snprintf(name, name_len, "%s",
                 sqlite3_column_text(st, 0) ? (const char *)sqlite3_column_text(st, 0) : "");
        if (enabled)
            *enabled = sqlite3_column_int(st, 1) ? 1 : 0;
        snprintf(wan, wan_len, "%s",
                 sqlite3_column_text(st, 2) ? (const char *)sqlite3_column_text(st, 2) : "");
        snprintf(method, method_len, "%s",
                 sqlite3_column_text(st, 3) ? (const char *)sqlite3_column_text(st, 3) : "icmp");
        if (targets)
            *targets = flowd_json_parse_or_array((const char *)sqlite3_column_text(st, 4));
        if (interval_s)
            *interval_s = sqlite3_column_int(st, 5);
        if (timeout_ms)
            *timeout_ms = sqlite3_column_int(st, 6);
        if (loss_threshold_pct)
            *loss_threshold_pct = sqlite3_column_int(st, 7);
        if (latency_threshold_ms)
            *latency_threshold_ms = sqlite3_column_int(st, 8);
        if (fail_count)
            *fail_count = sqlite3_column_int(st, 9);
        if (recover_count)
            *recover_count = sqlite3_column_int(st, 10);
        snprintf(remark, remark_len, "%s",
                 sqlite3_column_text(st, 11) ? (const char *)sqlite3_column_text(st, 11) : "");
        sqlite3_finalize(st);
        return 1;
    }
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

static int flowd_wan_health_save_one(struct json_object *body)
{
    sqlite3_stmt *st;
    struct json_object *targets = NULL;
    char generated_id[FLOWD_MAX_ID];
    char name_buf[129] = "";
    char wan_buf[129] = "";
    char method_buf[32] = "icmp";
    char remark_buf[257] = "";
    const char *id, *name, *wan, *method, *targets_s, *remark;
    int enabled, interval_s, timeout_ms, loss_threshold_pct;
    int latency_threshold_ms, fail_count, recover_count, ok = 0;
    int64_t now = flowd_now_s();

    if (!body || !json_object_is_type(body, json_type_object))
        return -1;
    id = flowd_json_str(body, "id", "");
    if (!id[0]) {
        flowd_make_id("wan-health", generated_id, sizeof(generated_id));
        id = generated_id;
    }
    enabled = 1;
    interval_s = 5;
    timeout_ms = 1000;
    loss_threshold_pct = 50;
    latency_threshold_ms = 300;
    fail_count = 3;
    recover_count = 2;
    if (body && flowd_json_str(body, "id", "")[0]) {
        int existing = flowd_wan_health_load_existing(id, name_buf, sizeof(name_buf),
                                                      &enabled, wan_buf, sizeof(wan_buf),
                                                      method_buf, sizeof(method_buf),
                                                      &targets, &interval_s, &timeout_ms,
                                                      &loss_threshold_pct, &latency_threshold_ms,
                                                      &fail_count, &recover_count,
                                                      remark_buf, sizeof(remark_buf));
        if (existing < 0)
            return -1;
    }
    name = flowd_json_str(body, "name", name_buf);
    enabled = flowd_json_bool(body, "enabled", enabled);
    wan = flowd_json_str(body, "wan", wan_buf);
    method = flowd_json_str(body, "method", method_buf);
    if (flowd_wan_health_targets_present(body)) {
        if (targets)
            json_object_put(targets);
        targets = flowd_wan_health_targets_from_body(body);
    } else if (!targets) {
        targets = json_object_new_array();
    }
    interval_s = flowd_json_int(body, "interval_s", interval_s);
    timeout_ms = flowd_json_int(body, "timeout_ms", timeout_ms);
    loss_threshold_pct = flowd_json_int(body, "loss_threshold_pct", loss_threshold_pct);
    latency_threshold_ms = flowd_json_int(body, "latency_threshold_ms", latency_threshold_ms);
    fail_count = flowd_json_int(body, "fail_count", fail_count);
    recover_count = flowd_json_int(body, "recover_count", recover_count);
    remark = flowd_json_str(body, "remark", remark_buf);
    if (!flowd_id_ok(id) || !flowd_text_ok(name, 128) || !flowd_token_ok(wan, 128) ||
        !flowd_wan_health_method_ok(method) || !flowd_wan_health_targets_ok(targets) ||
        interval_s < 1 || interval_s > 3600 || timeout_ms < 100 || timeout_ms > 60000 ||
        loss_threshold_pct < 0 || loss_threshold_pct > 100 ||
        latency_threshold_ms < 1 || latency_threshold_ms > 600000 ||
        fail_count < 1 || fail_count > 100 || recover_count < 1 || recover_count > 100 ||
        !flowd_text_ok(remark, 256)) {
        if (targets)
            json_object_put(targets);
        return -1;
    }
    targets_s = json_object_to_json_string_ext(targets, JSON_C_TO_STRING_PLAIN);
    if (!targets_s) {
        json_object_put(targets);
        return -1;
    }
    st = flowd_config_prepare(
        "INSERT INTO flowd_wan_health"
        "(id,name,enabled,wan,method,targets_json,interval_s,timeout_ms,loss_threshold_pct,"
        "latency_threshold_ms,fail_count,recover_count,remark,created_at,updated_at) "
        "VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?14) "
        "ON CONFLICT(id) DO UPDATE SET name=excluded.name,enabled=excluded.enabled,wan=excluded.wan,"
        "method=excluded.method,targets_json=excluded.targets_json,interval_s=excluded.interval_s,"
        "timeout_ms=excluded.timeout_ms,loss_threshold_pct=excluded.loss_threshold_pct,"
        "latency_threshold_ms=excluded.latency_threshold_ms,fail_count=excluded.fail_count,"
        "recover_count=excluded.recover_count,remark=excluded.remark,updated_at=excluded.updated_at");
    if (st) {
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, name, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 3, enabled ? 1 : 0);
        sqlite3_bind_text(st, 4, wan, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 5, method, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 6, targets_s, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 7, interval_s);
        sqlite3_bind_int(st, 8, timeout_ms);
        sqlite3_bind_int(st, 9, loss_threshold_pct);
        sqlite3_bind_int(st, 10, latency_threshold_ms);
        sqlite3_bind_int(st, 11, fail_count);
        sqlite3_bind_int(st, 12, recover_count);
        sqlite3_bind_text(st, 13, remark, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 14, now);
        ok = sqlite3_step(st) == SQLITE_DONE;
        sqlite3_finalize(st);
    }
    json_object_put(targets);
    return ok ? 0 : -1;
}

struct json_object *flowd_wan_health_update(struct json_object *body)
{
    struct json_object *arr = NULL;
    int ok = 1, saved = 0, i, n;
    struct json_object *resp;

    if (!body || !json_object_is_type(body, json_type_object))
        return flowd_error("invalid_request", "wan health body must be an object");
    if (json_object_object_get_ex(body, "checks", &arr) && arr &&
        json_object_is_type(arr, json_type_array)) {
        n = json_object_array_length(arr);
        for (i = 0; i < n; i++) {
            if (flowd_wan_health_save_one(json_object_array_get_idx(arr, i)) == 0)
                saved++;
            else
                ok = 0;
        }
    } else {
        ok = flowd_wan_health_save_one(body) == 0;
        saved = ok ? 1 : 0;
    }
    resp = flowd_wan_health_json(NULL);
    flowd_response_set_ok(resp, ok);
    json_object_object_add(resp, "saved", json_object_new_int(saved));
    if (!ok)
        json_object_object_add(resp, "error", json_object_new_string("partial_or_failed_save"));
    return resp;
}

struct json_object *flowd_wan_health_delete(struct json_object *body)
{
    sqlite3_stmt *st;
    const char *id = flowd_json_str(body, "id", "");
    int ok = 0;
    struct json_object *resp;

    if (!flowd_id_ok(id))
        return flowd_error("invalid_id", "invalid wan health id");
    st = flowd_config_prepare("DELETE FROM flowd_wan_health WHERE id=?1");
    if (st) {
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        ok = sqlite3_step(st) == SQLITE_DONE && sqlite3_changes(g_flowd_config_db) > 0;
        sqlite3_finalize(st);
    }
    resp = flowd_wan_health_json(NULL);
    flowd_response_set_ok(resp, ok);
    json_object_object_add(resp, "deleted", json_object_new_boolean(ok));
    if (!ok)
        json_object_object_add(resp, "error", json_object_new_string("not_found"));
    return resp;
}

static void flowd_wan_health_compile_json(struct json_object *out)
{
    sqlite3_stmt *st;
    struct json_object *checks = json_object_new_array();
    int enabled_count = 0;

    st = flowd_config_prepare(
        "SELECT id,name,enabled,wan,method,targets_json,interval_s,timeout_ms,"
        "loss_threshold_pct,latency_threshold_ms,fail_count,recover_count,remark,updated_at "
        "FROM flowd_wan_health WHERE enabled=1 ORDER BY wan,id");
    if (st) {
        while (sqlite3_step(st) == SQLITE_ROW) {
            const char *targets_s = (const char *)sqlite3_column_text(st, 5);
            struct json_object *o = json_object_new_object();

            json_object_object_add(o, "id", flowd_sqlite_text_json(st, 0));
            json_object_object_add(o, "name", flowd_sqlite_text_json(st, 1));
            json_object_object_add(o, "wan", flowd_sqlite_text_json(st, 3));
            json_object_object_add(o, "method", flowd_sqlite_text_json(st, 4));
            json_object_object_add(o, "targets", flowd_json_parse_or_array(targets_s));
            json_object_object_add(o, "interval_s", json_object_new_int(sqlite3_column_int(st, 6)));
            json_object_object_add(o, "timeout_ms", json_object_new_int(sqlite3_column_int(st, 7)));
            json_object_object_add(o, "loss_threshold_pct", json_object_new_int(sqlite3_column_int(st, 8)));
            json_object_object_add(o, "latency_threshold_ms", json_object_new_int(sqlite3_column_int(st, 9)));
            json_object_object_add(o, "fail_count", json_object_new_int(sqlite3_column_int(st, 10)));
            json_object_object_add(o, "recover_count", json_object_new_int(sqlite3_column_int(st, 11)));
            json_object_object_add(o, "runtime_kind", json_object_new_string("wan_health_check"));
            json_object_object_add(o, "state_store", json_object_new_string(FLOWD_DEFAULT_FLOW_DB_PATH));
            json_object_object_add(o, "state", json_object_new_string("planned"));
            json_object_object_add(o, "mutates_dataplane", json_object_new_boolean(0));
            json_object_array_add(checks, o);
            enabled_count++;
        }
        sqlite3_finalize(st);
    }
    json_object_object_add(out, "total", json_object_new_int(flowd_count_sql("SELECT COUNT(*) FROM flowd_wan_health")));
    json_object_object_add(out, "enabled", json_object_new_int(enabled_count));
    json_object_object_add(out, "checks", checks);
}

static int flowd_split_action_ok(const char *action)
{
    return action && (!strcmp(action, "route") || !strcmp(action, "bypass") ||
                      !strcmp(action, "block") || !strcmp(action, "mark"));
}

static int flowd_split_fallback_ok(const char *fallback)
{
    return fallback && (!strcmp(fallback, "main") || !strcmp(fallback, "bypass") ||
                        !strcmp(fallback, "block") || !strcmp(fallback, "drop") ||
                        !strcmp(fallback, "failover"));
}

static int flowd_split_proto_ok(const char *proto)
{
    char *end = NULL;
    long n;

    if (!proto || !proto[0])
        return 0;
    if (!strcmp(proto, "any") || !strcmp(proto, "all") || !strcmp(proto, "tcp") ||
        !strcmp(proto, "udp") || !strcmp(proto, "icmp") || !strcmp(proto, "icmpv6") ||
        !strcmp(proto, "gre") || !strcmp(proto, "esp") || !strcmp(proto, "ah"))
        return 1;
    n = strtol(proto, &end, 10);
    return end && *end == '\0' && n >= 0 && n <= 255;
}

static int flowd_split_port_expr_ok(const char *port)
{
    if (!port || !port[0])
        return 1;
    if (!strcmp(port, "any"))
        return 1;
    return flowd_token_ok(port, 64);
}

static int flowd_optional_id_ok(const char *id)
{
    return !id || !id[0] || flowd_id_ok(id);
}

static struct json_object *flowd_match_from_body(struct json_object *body)
{
    struct json_object *v = NULL;
    struct json_object *parsed = NULL;

    if (!body || !json_object_is_type(body, json_type_object))
        return json_object_new_object();
    if (!json_object_object_get_ex(body, "match", &v) &&
        !json_object_object_get_ex(body, "match_json", &v))
        return json_object_new_object();
    if (!v)
        return json_object_new_object();
    if (json_object_is_type(v, json_type_string)) {
        parsed = json_tokener_parse(json_object_get_string(v));
        if (parsed)
            return parsed;
    }
    return json_object_get(v);
}

static int flowd_id_exists_in(const char *table, const char *id)
{
    sqlite3_stmt *st;
    char sql[128];
    int exists = 0;

    if (!id || !id[0])
        return 1;
    if (!flowd_id_ok(id))
        return 0;
    if (strcmp(table, "flowd_objects") && strcmp(table, "flowd_route_groups") &&
        strcmp(table, "flowd_qos_classes"))
        return 0;
    snprintf(sql, sizeof(sql), "SELECT 1 FROM %s WHERE id=?1 LIMIT 1", table);
    st = flowd_config_prepare(sql);
    if (!st)
        return 0;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    exists = sqlite3_step(st) == SQLITE_ROW;
    sqlite3_finalize(st);
    return exists ? 1 : 0;
}

static void flowd_split_rule_missing_ref(struct json_object *missing,
                                         const char *field, const char *id)
{
    struct json_object *o;

    if (!missing || !field)
        return;
    o = json_object_new_object();
    json_object_object_add(o, "field", json_object_new_string(field));
    json_object_object_add(o, "id", json_object_new_string(id ? id : ""));
    json_object_array_add(missing, o);
}

static void flowd_split_rule_refs_json(struct json_object *o,
                                       const char *target_group,
                                       const char *src_object,
                                       const char *dst_object,
                                       const char *app_object,
                                       const char *service_object,
                                       const char *time_object)
{
    struct json_object *refs = json_object_new_object();

    json_object_object_add(refs, "target_group", json_object_new_string(target_group ? target_group : ""));
    json_object_object_add(refs, "src_object", json_object_new_string(src_object ? src_object : ""));
    json_object_object_add(refs, "dst_object", json_object_new_string(dst_object ? dst_object : ""));
    json_object_object_add(refs, "app_object", json_object_new_string(app_object ? app_object : ""));
    json_object_object_add(refs, "service_object", json_object_new_string(service_object ? service_object : ""));
    json_object_object_add(refs, "time_object", json_object_new_string(time_object ? time_object : ""));
    json_object_object_add(o, "refs", refs);
}

static void flowd_split_rule_row_json(struct json_object *arr, sqlite3_stmt *st)
{
    const char *match_s = (const char *)sqlite3_column_text(st, 16);
    const char *target_group = (const char *)sqlite3_column_text(st, 5);
    const char *src_object = (const char *)sqlite3_column_text(st, 8);
    const char *dst_object = (const char *)sqlite3_column_text(st, 9);
    const char *app_object = (const char *)sqlite3_column_text(st, 10);
    const char *service_object = (const char *)sqlite3_column_text(st, 11);
    const char *time_object = (const char *)sqlite3_column_text(st, 12);
    struct json_object *o = json_object_new_object();

    json_object_object_add(o, "id", flowd_sqlite_text_json(st, 0));
    json_object_object_add(o, "name", flowd_sqlite_text_json(st, 1));
    json_object_object_add(o, "enabled", json_object_new_boolean(sqlite3_column_int(st, 2)));
    json_object_object_add(o, "priority", json_object_new_int(sqlite3_column_int(st, 3)));
    json_object_object_add(o, "action", flowd_sqlite_text_json(st, 4));
    json_object_object_add(o, "target_group", json_object_new_string(target_group ? target_group : ""));
    json_object_object_add(o, "fallback", flowd_sqlite_text_json(st, 6));
    json_object_object_add(o, "family", flowd_sqlite_text_json(st, 7));
    flowd_split_rule_refs_json(o, target_group, src_object, dst_object, app_object,
                               service_object, time_object);
    json_object_object_add(o, "proto", flowd_sqlite_text_json(st, 13));
    json_object_object_add(o, "src_port", flowd_sqlite_text_json(st, 14));
    json_object_object_add(o, "dst_port", flowd_sqlite_text_json(st, 15));
    json_object_object_add(o, "match", flowd_json_parse_or_object(match_s));
    json_object_object_add(o, "remark", flowd_sqlite_text_json(st, 17));
    json_object_object_add(o, "updated_at", json_object_new_int64(sqlite3_column_int64(st, 18)));
    json_object_array_add(arr, o);
}

struct json_object *flowd_split_rules_json(struct json_object *body)
{
    sqlite3_stmt *st = NULL;
    struct json_object *resp = json_object_new_object();
    struct json_object *arr = json_object_new_array();
    const char *id = flowd_json_str(body, "id", "");
    int include_disabled = flowd_json_bool(body, "include_disabled", 1);
    int ok = 1;
    const char *error = "";

    if (id && id[0] && !flowd_id_ok(id))
        return flowd_error("invalid_id", "invalid flowd split rule id");
    if (id && id[0]) {
        st = flowd_config_prepare(
            "SELECT id,name,enabled,priority,action,target_group,fallback,family,src_object,dst_object,"
            "app_object,service_object,time_object,proto,src_port,dst_port,match_json,remark,updated_at "
            "FROM flowd_split_rules WHERE id=?1");
        if (st)
            sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    } else {
        st = flowd_config_prepare(
            "SELECT id,name,enabled,priority,action,target_group,fallback,family,src_object,dst_object,"
            "app_object,service_object,time_object,proto,src_port,dst_port,match_json,remark,updated_at "
            "FROM flowd_split_rules WHERE (?1 OR enabled=1) ORDER BY priority,id");
        if (st)
            sqlite3_bind_int(st, 1, include_disabled ? 1 : 0);
    }
    if (st) {
        ok = flowd_collect_rows(st, arr, flowd_split_rule_row_json, "split rules");
        if (!ok)
            error = "split_rules_unavailable";
        sqlite3_finalize(st);
    } else {
        ok = 0;
        error = "split_rules_unavailable";
    }
    flowd_list_total_add(resp, &ok, &error, "SELECT COUNT(*) FROM flowd_split_rules",
                         "split_rules_count_unavailable");
    json_object_object_add(resp, "ok", json_object_new_boolean(ok));
    json_object_object_add(resp, "rules", arr);
    if (error[0])
        json_object_object_add(resp, "error", json_object_new_string(error));
    return resp;
}

static int flowd_split_rule_load_existing(const char *id,
                                          char *name, size_t name_len,
                                          int *enabled, int *priority,
                                          char *action, size_t action_len,
                                          char *target_group, size_t target_group_len,
                                          char *fallback, size_t fallback_len,
                                          char *family, size_t family_len,
                                          char *src_object, size_t src_object_len,
                                          char *dst_object, size_t dst_object_len,
                                          char *app_object, size_t app_object_len,
                                          char *service_object, size_t service_object_len,
                                          char *time_object, size_t time_object_len,
                                          char *proto, size_t proto_len,
                                          char *src_port, size_t src_port_len,
                                          char *dst_port, size_t dst_port_len,
                                          char *match_json, size_t match_json_len,
                                          char *remark, size_t remark_len)
{
    sqlite3_stmt *st;
    int rc;

    if (!flowd_id_ok(id))
        return -1;
    st = flowd_config_prepare(
        "SELECT name,enabled,priority,action,target_group,fallback,family,src_object,dst_object,"
        "app_object,service_object,time_object,proto,src_port,dst_port,match_json,remark "
        "FROM flowd_split_rules WHERE id=?1");
    if (!st)
        return -1;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) {
        snprintf(name, name_len, "%s",
                 sqlite3_column_text(st, 0) ? (const char *)sqlite3_column_text(st, 0) : "");
        if (enabled)
            *enabled = sqlite3_column_int(st, 1) ? 1 : 0;
        if (priority)
            *priority = sqlite3_column_int(st, 2);
        snprintf(action, action_len, "%s",
                 sqlite3_column_text(st, 3) ? (const char *)sqlite3_column_text(st, 3) : "route");
        snprintf(target_group, target_group_len, "%s",
                 sqlite3_column_text(st, 4) ? (const char *)sqlite3_column_text(st, 4) : "");
        snprintf(fallback, fallback_len, "%s",
                 sqlite3_column_text(st, 5) ? (const char *)sqlite3_column_text(st, 5) : "main");
        snprintf(family, family_len, "%s",
                 sqlite3_column_text(st, 6) ? (const char *)sqlite3_column_text(st, 6) : "both");
        snprintf(src_object, src_object_len, "%s",
                 sqlite3_column_text(st, 7) ? (const char *)sqlite3_column_text(st, 7) : "");
        snprintf(dst_object, dst_object_len, "%s",
                 sqlite3_column_text(st, 8) ? (const char *)sqlite3_column_text(st, 8) : "");
        snprintf(app_object, app_object_len, "%s",
                 sqlite3_column_text(st, 9) ? (const char *)sqlite3_column_text(st, 9) : "");
        snprintf(service_object, service_object_len, "%s",
                 sqlite3_column_text(st, 10) ? (const char *)sqlite3_column_text(st, 10) : "");
        snprintf(time_object, time_object_len, "%s",
                 sqlite3_column_text(st, 11) ? (const char *)sqlite3_column_text(st, 11) : "");
        snprintf(proto, proto_len, "%s",
                 sqlite3_column_text(st, 12) ? (const char *)sqlite3_column_text(st, 12) : "any");
        snprintf(src_port, src_port_len, "%s",
                 sqlite3_column_text(st, 13) ? (const char *)sqlite3_column_text(st, 13) : "");
        snprintf(dst_port, dst_port_len, "%s",
                 sqlite3_column_text(st, 14) ? (const char *)sqlite3_column_text(st, 14) : "");
        snprintf(match_json, match_json_len, "%s",
                 sqlite3_column_text(st, 15) ? (const char *)sqlite3_column_text(st, 15) : "{}");
        snprintf(remark, remark_len, "%s",
                 sqlite3_column_text(st, 16) ? (const char *)sqlite3_column_text(st, 16) : "");
        sqlite3_finalize(st);
        return 1;
    }
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

static int flowd_split_rule_save_one(struct json_object *body)
{
    sqlite3_stmt *st;
    struct json_object *match = NULL;
    struct json_object *match_body = NULL;
    char generated_id[FLOWD_MAX_ID];
    char name_buf[129] = "";
    char action_buf[32] = "route";
    char target_group_buf[FLOWD_MAX_ID] = "";
    char fallback_buf[32] = "main";
    char family_buf[16] = "both";
    char src_object_buf[FLOWD_MAX_ID] = "";
    char dst_object_buf[FLOWD_MAX_ID] = "";
    char app_object_buf[FLOWD_MAX_ID] = "";
    char service_object_buf[FLOWD_MAX_ID] = "";
    char time_object_buf[FLOWD_MAX_ID] = "";
    char proto_buf[32] = "any";
    char src_port_buf[65] = "";
    char dst_port_buf[65] = "";
    char match_json_buf[FLOWD_MAX_JSON + 1] = "{}";
    char remark_buf[257] = "";
    const char *id, *name, *action, *target_group, *fallback, *family;
    const char *family_norm;
    const char *src_object, *dst_object, *app_object, *service_object, *time_object;
    const char *proto, *src_port, *dst_port, *remark, *match_s;
    int enabled, priority, ok = 0;
    int64_t now = flowd_now_s();

    if (!body || !json_object_is_type(body, json_type_object))
        return -1;
    enabled = 1;
    priority = 1000;
    id = flowd_json_str(body, "id", "");
    if (!id[0]) {
        flowd_make_id("split-rule", generated_id, sizeof(generated_id));
        id = generated_id;
    } else {
        int existing;

        existing = flowd_split_rule_load_existing(id, name_buf, sizeof(name_buf),
                                                  &enabled, &priority,
                                                  action_buf, sizeof(action_buf),
                                                  target_group_buf, sizeof(target_group_buf),
                                                  fallback_buf, sizeof(fallback_buf),
                                                  family_buf, sizeof(family_buf),
                                                  src_object_buf, sizeof(src_object_buf),
                                                  dst_object_buf, sizeof(dst_object_buf),
                                                  app_object_buf, sizeof(app_object_buf),
                                                  service_object_buf, sizeof(service_object_buf),
                                                  time_object_buf, sizeof(time_object_buf),
                                                  proto_buf, sizeof(proto_buf),
                                                  src_port_buf, sizeof(src_port_buf),
                                                  dst_port_buf, sizeof(dst_port_buf),
                                                  match_json_buf, sizeof(match_json_buf),
                                                  remark_buf, sizeof(remark_buf));
        if (existing < 0)
            return -1;
    }
    name = flowd_json_str(body, "name", name_buf);
    enabled = flowd_json_bool(body, "enabled", enabled);
    priority = flowd_json_int(body, "priority", priority);
    action = flowd_json_str(body, "action", action_buf);
    target_group = flowd_json_str(body, "target_group", target_group_buf);
    fallback = flowd_json_str(body, "fallback", fallback_buf);
    family = flowd_json_str(body, "family", family_buf);
    src_object = flowd_json_str(body, "src_object", src_object_buf);
    dst_object = flowd_json_str(body, "dst_object", dst_object_buf);
    app_object = flowd_json_str(body, "app_object", app_object_buf);
    service_object = flowd_json_str(body, "service_object", service_object_buf);
    time_object = flowd_json_str(body, "time_object", time_object_buf);
    proto = flowd_json_str(body, "proto", proto_buf);
    src_port = flowd_json_str(body, "src_port", src_port_buf);
    dst_port = flowd_json_str(body, "dst_port", dst_port_buf);
    remark = flowd_json_str(body, "remark", remark_buf);
    if (json_object_object_get_ex(body, "match", &match_body) ||
        json_object_object_get_ex(body, "match_json", &match_body)) {
        match = flowd_match_from_body(body);
    } else {
        match = json_tokener_parse(match_json_buf);
        if (!match)
            match = json_object_new_object();
    }
    family_norm = flowd_policy_family(family);
    if (!flowd_id_ok(id) || !flowd_text_ok(name, 128) || priority < 0 ||
        priority > 1000000 || !flowd_split_action_ok(action) ||
        !flowd_optional_id_ok(target_group) || !flowd_split_fallback_ok(fallback) ||
        !family_norm || !flowd_optional_id_ok(src_object) ||
        !flowd_optional_id_ok(dst_object) || !flowd_optional_id_ok(app_object) ||
        !flowd_optional_id_ok(service_object) || !flowd_optional_id_ok(time_object) ||
        !flowd_split_proto_ok(proto) || !flowd_split_port_expr_ok(src_port) ||
        !flowd_split_port_expr_ok(dst_port) || !flowd_text_ok(remark, 256) ||
        !match || !json_object_is_type(match, json_type_object) ||
        !flowd_json_fits(match, FLOWD_MAX_JSON)) {
        if (match)
            json_object_put(match);
        return -1;
    }
    if (!strcmp(action, "route") && !target_group[0]) {
        json_object_put(match);
        return -1;
    }
    match_s = json_object_to_json_string_ext(match, JSON_C_TO_STRING_PLAIN);
    if (!match_s) {
        json_object_put(match);
        return -1;
    }
    st = flowd_config_prepare(
        "INSERT INTO flowd_split_rules"
        "(id,name,enabled,priority,action,target_group,fallback,family,src_object,dst_object,"
        "app_object,service_object,time_object,proto,src_port,dst_port,match_json,remark,created_at,updated_at) "
        "VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?19) "
        "ON CONFLICT(id) DO UPDATE SET name=excluded.name,enabled=excluded.enabled,"
        "priority=excluded.priority,action=excluded.action,target_group=excluded.target_group,"
        "fallback=excluded.fallback,family=excluded.family,src_object=excluded.src_object,"
        "dst_object=excluded.dst_object,app_object=excluded.app_object,service_object=excluded.service_object,"
        "time_object=excluded.time_object,proto=excluded.proto,src_port=excluded.src_port,"
        "dst_port=excluded.dst_port,match_json=excluded.match_json,remark=excluded.remark,"
        "updated_at=excluded.updated_at");
    if (st) {
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, name, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 3, enabled ? 1 : 0);
        sqlite3_bind_int(st, 4, priority);
        sqlite3_bind_text(st, 5, action, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 6, target_group, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 7, fallback, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 8, family_norm, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 9, src_object, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 10, dst_object, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 11, app_object, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 12, service_object, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 13, time_object, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 14, proto, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 15, src_port, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 16, dst_port, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 17, match_s, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 18, remark, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 19, now);
        ok = sqlite3_step(st) == SQLITE_DONE;
        sqlite3_finalize(st);
    }
    json_object_put(match);
    return ok ? 0 : -1;
}

struct json_object *flowd_split_rule_update(struct json_object *body)
{
    struct json_object *arr = NULL;
    int ok = 1, saved = 0, i, n;
    struct json_object *resp;

    if (!body || !json_object_is_type(body, json_type_object))
        return flowd_error("invalid_request", "split rule body must be an object");
    if (json_object_object_get_ex(body, "rules", &arr) && arr &&
        json_object_is_type(arr, json_type_array)) {
        n = json_object_array_length(arr);
        for (i = 0; i < n; i++) {
            if (flowd_split_rule_save_one(json_object_array_get_idx(arr, i)) == 0)
                saved++;
            else
                ok = 0;
        }
    } else {
        ok = flowd_split_rule_save_one(body) == 0;
        saved = ok ? 1 : 0;
    }
    resp = flowd_split_rules_json(NULL);
    flowd_response_set_ok(resp, ok);
    json_object_object_add(resp, "saved", json_object_new_int(saved));
    if (!ok)
        json_object_object_add(resp, "error", json_object_new_string("partial_or_failed_save"));
    return resp;
}

struct json_object *flowd_split_rule_delete(struct json_object *body)
{
    sqlite3_stmt *st;
    const char *id = flowd_json_str(body, "id", "");
    int ok = 0;
    struct json_object *resp;

    if (!flowd_id_ok(id))
        return flowd_error("invalid_id", "invalid flowd split rule id");
    st = flowd_config_prepare("DELETE FROM flowd_split_rules WHERE id=?1");
    if (st) {
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        ok = sqlite3_step(st) == SQLITE_DONE && sqlite3_changes(g_flowd_config_db) > 0;
        sqlite3_finalize(st);
    }
    resp = flowd_split_rules_json(NULL);
    flowd_response_set_ok(resp, ok);
    json_object_object_add(resp, "deleted", json_object_new_boolean(ok));
    if (!ok)
        json_object_object_add(resp, "error", json_object_new_string("not_found"));
    return resp;
}

static int flowd_split_rules_compile_json(struct json_object *out)
{
    sqlite3_stmt *st;
    struct json_object *compiled = json_object_new_array();
    int enabled_count = 0;
    int missing_refs = 0;

    st = flowd_config_prepare(
        "SELECT id,name,enabled,priority,action,target_group,fallback,family,src_object,dst_object,"
        "app_object,service_object,time_object,proto,src_port,dst_port,match_json,remark,updated_at "
        "FROM flowd_split_rules WHERE enabled=1 ORDER BY priority,id");
    if (st) {
        while (sqlite3_step(st) == SQLITE_ROW) {
            const char *id = (const char *)sqlite3_column_text(st, 0);
            const char *action = (const char *)sqlite3_column_text(st, 4);
            const char *target_group = (const char *)sqlite3_column_text(st, 5);
            const char *src_object = (const char *)sqlite3_column_text(st, 8);
            const char *dst_object = (const char *)sqlite3_column_text(st, 9);
            const char *app_object = (const char *)sqlite3_column_text(st, 10);
            const char *service_object = (const char *)sqlite3_column_text(st, 11);
            const char *time_object = (const char *)sqlite3_column_text(st, 12);
            const char *match_s = (const char *)sqlite3_column_text(st, 16);
            struct json_object *o = json_object_new_object();
            struct json_object *missing = json_object_new_array();
            int local_missing = 0;

            if (action && !strcmp(action, "route") &&
                (!target_group || !target_group[0] ||
                 !flowd_id_exists_in("flowd_route_groups", target_group))) {
                flowd_split_rule_missing_ref(missing, "target_group", target_group);
                local_missing++;
            }
            if (!flowd_id_exists_in("flowd_objects", src_object)) {
                flowd_split_rule_missing_ref(missing, "src_object", src_object);
                local_missing++;
            }
            if (!flowd_id_exists_in("flowd_objects", dst_object)) {
                flowd_split_rule_missing_ref(missing, "dst_object", dst_object);
                local_missing++;
            }
            if (!flowd_id_exists_in("flowd_objects", app_object)) {
                flowd_split_rule_missing_ref(missing, "app_object", app_object);
                local_missing++;
            }
            if (!flowd_id_exists_in("flowd_objects", service_object)) {
                flowd_split_rule_missing_ref(missing, "service_object", service_object);
                local_missing++;
            }
            if (!flowd_id_exists_in("flowd_objects", time_object)) {
                flowd_split_rule_missing_ref(missing, "time_object", time_object);
                local_missing++;
            }
            json_object_object_add(o, "id", json_object_new_string(id ? id : ""));
            json_object_object_add(o, "name", flowd_sqlite_text_json(st, 1));
            json_object_object_add(o, "priority", json_object_new_int(sqlite3_column_int(st, 3)));
            json_object_object_add(o, "action", json_object_new_string(action ? action : ""));
            json_object_object_add(o, "target_group", json_object_new_string(target_group ? target_group : ""));
            json_object_object_add(o, "fallback", flowd_sqlite_text_json(st, 6));
            json_object_object_add(o, "family", flowd_sqlite_text_json(st, 7));
            flowd_split_rule_refs_json(o, target_group, src_object, dst_object, app_object,
                                       service_object, time_object);
            json_object_object_add(o, "proto", flowd_sqlite_text_json(st, 13));
            json_object_object_add(o, "src_port", flowd_sqlite_text_json(st, 14));
            json_object_object_add(o, "dst_port", flowd_sqlite_text_json(st, 15));
            json_object_object_add(o, "match", flowd_json_parse_or_object(match_s));
            json_object_object_add(o, "runtime_kind", json_object_new_string("fwmark_split_rule"));
            json_object_object_add(o, "state", json_object_new_string(local_missing ? "blocked" : "planned"));
            json_object_object_add(o, "missing_refs", missing);
            json_object_object_add(o, "mutates_dataplane", json_object_new_boolean(0));
            json_object_array_add(compiled, o);
            missing_refs += local_missing;
            enabled_count++;
        }
        sqlite3_finalize(st);
    }
    json_object_object_add(out, "total", json_object_new_int(flowd_count_sql("SELECT COUNT(*) FROM flowd_split_rules")));
    json_object_object_add(out, "enabled", json_object_new_int(enabled_count));
    json_object_object_add(out, "missing_refs", json_object_new_int(missing_refs));
    json_object_object_add(out, "compiled", compiled);
    return missing_refs;
}

static int flowd_object_exists_with_type(const char *id, const char *type)
{
    sqlite3_stmt *st;
    int exists = 0;

    if (!id || !id[0] || !type || !type[0] || !flowd_id_ok(id))
        return 0;
    st = flowd_config_prepare(
        "SELECT 1 FROM flowd_objects WHERE id=?1 AND type=?2 LIMIT 1");
    if (!st)
        return 0;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, type, -1, SQLITE_TRANSIENT);
    exists = sqlite3_step(st) == SQLITE_ROW;
    sqlite3_finalize(st);
    return exists ? 1 : 0;
}

static void flowd_domain_rule_refs_json(struct json_object *o,
                                        const char *domain_object,
                                        const char *src_object,
                                        const char *time_object,
                                        const char *route_group)
{
    struct json_object *refs = json_object_new_object();

    json_object_object_add(refs, "domain_object", json_object_new_string(domain_object ? domain_object : ""));
    json_object_object_add(refs, "src_object", json_object_new_string(src_object ? src_object : ""));
    json_object_object_add(refs, "time_object", json_object_new_string(time_object ? time_object : ""));
    json_object_object_add(refs, "route_group", json_object_new_string(route_group ? route_group : ""));
    json_object_object_add(o, "refs", refs);
}

static void flowd_domain_rule_row_json(struct json_object *arr, sqlite3_stmt *st)
{
    const char *domain_object = (const char *)sqlite3_column_text(st, 5);
    const char *src_object = (const char *)sqlite3_column_text(st, 6);
    const char *time_object = (const char *)sqlite3_column_text(st, 7);
    const char *route_group = (const char *)sqlite3_column_text(st, 8);
    struct json_object *o = json_object_new_object();

    json_object_object_add(o, "id", flowd_sqlite_text_json(st, 0));
    json_object_object_add(o, "name", flowd_sqlite_text_json(st, 1));
    json_object_object_add(o, "enabled", json_object_new_boolean(sqlite3_column_int(st, 2)));
    json_object_object_add(o, "priority", json_object_new_int(sqlite3_column_int(st, 3)));
    json_object_object_add(o, "action", flowd_sqlite_text_json(st, 4));
    json_object_object_add(o, "domain_object", json_object_new_string(domain_object ? domain_object : ""));
    json_object_object_add(o, "src_object", json_object_new_string(src_object ? src_object : ""));
    json_object_object_add(o, "time_object", json_object_new_string(time_object ? time_object : ""));
    json_object_object_add(o, "route_group", json_object_new_string(route_group ? route_group : ""));
    json_object_object_add(o, "fallback", flowd_sqlite_text_json(st, 9));
    json_object_object_add(o, "family", flowd_sqlite_text_json(st, 10));
    json_object_object_add(o, "mark", flowd_sqlite_text_json(st, 11));
    json_object_object_add(o, "log_event", json_object_new_boolean(sqlite3_column_int(st, 12)));
    flowd_domain_rule_refs_json(o, domain_object, src_object, time_object, route_group);
    json_object_object_add(o, "runtime_kind", json_object_new_string("domain_route_rule"));
    json_object_object_add(o, "remark", flowd_sqlite_text_json(st, 13));
    json_object_object_add(o, "updated_at", json_object_new_int64(sqlite3_column_int64(st, 14)));
    json_object_array_add(arr, o);
}

struct json_object *flowd_domain_rules_json(struct json_object *body)
{
    sqlite3_stmt *st = NULL;
    struct json_object *resp = json_object_new_object();
    struct json_object *arr = json_object_new_array();
    const char *id = flowd_json_str(body, "id", "");
    int include_disabled = flowd_json_bool(body, "include_disabled", 1);
    int ok = 1;
    const char *error = "";

    if (id && id[0] && !flowd_id_ok(id))
        return flowd_error("invalid_id", "invalid domain rule id");
    if (id && id[0]) {
        st = flowd_config_prepare(
            "SELECT id,name,enabled,priority,action,domain_object,src_object,time_object,route_group,"
            "fallback,family,mark,log_event,remark,updated_at FROM flowd_domain_rules WHERE id=?1");
        if (st)
            sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    } else {
        st = flowd_config_prepare(
            "SELECT id,name,enabled,priority,action,domain_object,src_object,time_object,route_group,"
            "fallback,family,mark,log_event,remark,updated_at FROM flowd_domain_rules "
            "WHERE (?1 OR enabled=1) ORDER BY priority,id");
        if (st)
            sqlite3_bind_int(st, 1, include_disabled ? 1 : 0);
    }
    if (st) {
        ok = flowd_collect_rows(st, arr, flowd_domain_rule_row_json, "domain rules");
        if (!ok)
            error = "domain_rules_unavailable";
        sqlite3_finalize(st);
    } else {
        ok = 0;
        error = "domain_rules_unavailable";
    }
    flowd_list_total_add(resp, &ok, &error, "SELECT COUNT(*) FROM flowd_domain_rules",
                         "domain_rules_count_unavailable");
    json_object_object_add(resp, "ok", json_object_new_boolean(ok));
    json_object_object_add(resp, "rules", arr);
    if (error[0])
        json_object_object_add(resp, "error", json_object_new_string(error));
    return resp;
}

static int flowd_domain_rule_load_existing(const char *id,
                                           char *name, size_t name_len,
                                           int *enabled, int *priority,
                                           char *action, size_t action_len,
                                           char *domain_object, size_t domain_object_len,
                                           char *src_object, size_t src_object_len,
                                           char *time_object, size_t time_object_len,
                                           char *route_group, size_t route_group_len,
                                           char *fallback, size_t fallback_len,
                                           char *family, size_t family_len,
                                           char *mark, size_t mark_len,
                                           int *log_event,
                                           char *remark, size_t remark_len)
{
    sqlite3_stmt *st;
    int rc;

    if (!flowd_id_ok(id))
        return -1;
    st = flowd_config_prepare(
        "SELECT name,enabled,priority,action,domain_object,src_object,time_object,route_group,"
        "fallback,family,mark,log_event,remark FROM flowd_domain_rules WHERE id=?1");
    if (!st)
        return -1;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) {
        snprintf(name, name_len, "%s",
                 sqlite3_column_text(st, 0) ? (const char *)sqlite3_column_text(st, 0) : "");
        if (enabled)
            *enabled = sqlite3_column_int(st, 1) ? 1 : 0;
        if (priority)
            *priority = sqlite3_column_int(st, 2);
        snprintf(action, action_len, "%s",
                 sqlite3_column_text(st, 3) ? (const char *)sqlite3_column_text(st, 3) : "route");
        snprintf(domain_object, domain_object_len, "%s",
                 sqlite3_column_text(st, 4) ? (const char *)sqlite3_column_text(st, 4) : "");
        snprintf(src_object, src_object_len, "%s",
                 sqlite3_column_text(st, 5) ? (const char *)sqlite3_column_text(st, 5) : "");
        snprintf(time_object, time_object_len, "%s",
                 sqlite3_column_text(st, 6) ? (const char *)sqlite3_column_text(st, 6) : "");
        snprintf(route_group, route_group_len, "%s",
                 sqlite3_column_text(st, 7) ? (const char *)sqlite3_column_text(st, 7) : "");
        snprintf(fallback, fallback_len, "%s",
                 sqlite3_column_text(st, 8) ? (const char *)sqlite3_column_text(st, 8) : "main");
        snprintf(family, family_len, "%s",
                 sqlite3_column_text(st, 9) ? (const char *)sqlite3_column_text(st, 9) : "both");
        snprintf(mark, mark_len, "%s",
                 sqlite3_column_text(st, 10) ? (const char *)sqlite3_column_text(st, 10) : "");
        if (log_event)
            *log_event = sqlite3_column_int(st, 11) ? 1 : 0;
        snprintf(remark, remark_len, "%s",
                 sqlite3_column_text(st, 12) ? (const char *)sqlite3_column_text(st, 12) : "");
        sqlite3_finalize(st);
        return 1;
    }
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

static int flowd_domain_rule_save_one(struct json_object *body)
{
    sqlite3_stmt *st;
    char generated_id[FLOWD_MAX_ID];
    char name_buf[129] = "";
    char action_buf[32] = "route";
    char domain_object_buf[FLOWD_MAX_ID] = "";
    char src_object_buf[FLOWD_MAX_ID] = "";
    char time_object_buf[FLOWD_MAX_ID] = "";
    char route_group_buf[FLOWD_MAX_ID] = "";
    char fallback_buf[32] = "main";
    char family_buf[16] = "both";
    char mark_buf[65] = "";
    char remark_buf[257] = "";
    const char *id, *name, *action, *domain_object, *src_object, *time_object;
    const char *route_group, *fallback, *family, *family_norm, *mark, *remark;
    int enabled, priority, log_event, ok = 0;
    int64_t now = flowd_now_s();

    if (!body || !json_object_is_type(body, json_type_object))
        return -1;
    enabled = 1;
    priority = 1000;
    log_event = 1;
    id = flowd_json_str(body, "id", "");
    if (!id[0]) {
        flowd_make_id("domain-rule", generated_id, sizeof(generated_id));
        id = generated_id;
    } else {
        int existing;

        existing = flowd_domain_rule_load_existing(id, name_buf, sizeof(name_buf),
                                                   &enabled, &priority,
                                                   action_buf, sizeof(action_buf),
                                                   domain_object_buf, sizeof(domain_object_buf),
                                                   src_object_buf, sizeof(src_object_buf),
                                                   time_object_buf, sizeof(time_object_buf),
                                                   route_group_buf, sizeof(route_group_buf),
                                                   fallback_buf, sizeof(fallback_buf),
                                                   family_buf, sizeof(family_buf),
                                                   mark_buf, sizeof(mark_buf),
                                                   &log_event, remark_buf, sizeof(remark_buf));
        if (existing < 0)
            return -1;
    }
    name = flowd_json_str(body, "name", name_buf);
    enabled = flowd_json_bool(body, "enabled", enabled);
    priority = flowd_json_int(body, "priority", priority);
    action = flowd_json_str(body, "action", action_buf);
    domain_object = flowd_json_str(body, "domain_object", domain_object_buf);
    src_object = flowd_json_str(body, "src_object", src_object_buf);
    time_object = flowd_json_str(body, "time_object", time_object_buf);
    route_group = flowd_json_str(body, "route_group", route_group_buf);
    fallback = flowd_json_str(body, "fallback", fallback_buf);
    family = flowd_json_str(body, "family", family_buf);
    mark = flowd_json_str(body, "mark", mark_buf);
    log_event = flowd_json_bool(body, "log_event", log_event);
    remark = flowd_json_str(body, "remark", remark_buf);
    family_norm = flowd_policy_family(family);
    if (!flowd_id_ok(id) || !flowd_text_ok(name, 128) || priority < 0 || priority > 1000000 ||
        !flowd_split_action_ok(action) || !flowd_id_ok(domain_object) ||
        !flowd_optional_id_ok(src_object) || !flowd_optional_id_ok(time_object) ||
        !flowd_optional_id_ok(route_group) || !flowd_split_fallback_ok(fallback) ||
        !family_norm || (mark[0] && !flowd_token_ok(mark, 64)) ||
        !flowd_text_ok(remark, 256))
        return -1;
    if (!strcmp(action, "route") && !route_group[0])
        return -1;
    if (!strcmp(action, "mark") && !mark[0])
        return -1;
    st = flowd_config_prepare(
        "INSERT INTO flowd_domain_rules"
        "(id,name,enabled,priority,action,domain_object,src_object,time_object,route_group,"
        "fallback,family,mark,log_event,remark,created_at,updated_at) "
        "VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?15) "
        "ON CONFLICT(id) DO UPDATE SET name=excluded.name,enabled=excluded.enabled,"
        "priority=excluded.priority,action=excluded.action,domain_object=excluded.domain_object,"
        "src_object=excluded.src_object,time_object=excluded.time_object,route_group=excluded.route_group,"
        "fallback=excluded.fallback,family=excluded.family,mark=excluded.mark,log_event=excluded.log_event,"
        "remark=excluded.remark,updated_at=excluded.updated_at");
    if (st) {
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, name, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 3, enabled ? 1 : 0);
        sqlite3_bind_int(st, 4, priority);
        sqlite3_bind_text(st, 5, action, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 6, domain_object, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 7, src_object, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 8, time_object, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 9, route_group, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 10, fallback, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 11, family_norm, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 12, mark, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 13, log_event ? 1 : 0);
        sqlite3_bind_text(st, 14, remark, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 15, now);
        ok = sqlite3_step(st) == SQLITE_DONE;
        sqlite3_finalize(st);
    }
    return ok ? 0 : -1;
}

struct json_object *flowd_domain_rule_update(struct json_object *body)
{
    struct json_object *arr = NULL;
    int ok = 1, saved = 0, i, n;
    struct json_object *resp;

    if (!body || !json_object_is_type(body, json_type_object))
        return flowd_error("invalid_request", "domain rule body must be an object");
    if (json_object_object_get_ex(body, "rules", &arr) && arr &&
        json_object_is_type(arr, json_type_array)) {
        n = json_object_array_length(arr);
        for (i = 0; i < n; i++) {
            if (flowd_domain_rule_save_one(json_object_array_get_idx(arr, i)) == 0)
                saved++;
            else
                ok = 0;
        }
    } else {
        ok = flowd_domain_rule_save_one(body) == 0;
        saved = ok ? 1 : 0;
    }
    resp = flowd_domain_rules_json(NULL);
    flowd_response_set_ok(resp, ok);
    json_object_object_add(resp, "saved", json_object_new_int(saved));
    if (!ok)
        json_object_object_add(resp, "error", json_object_new_string("partial_or_failed_save"));
    return resp;
}

struct json_object *flowd_domain_rule_delete(struct json_object *body)
{
    sqlite3_stmt *st;
    const char *id = flowd_json_str(body, "id", "");
    int ok = 0;
    struct json_object *resp;

    if (!flowd_id_ok(id))
        return flowd_error("invalid_id", "invalid domain rule id");
    st = flowd_config_prepare("DELETE FROM flowd_domain_rules WHERE id=?1");
    if (st) {
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        ok = sqlite3_step(st) == SQLITE_DONE && sqlite3_changes(g_flowd_config_db) > 0;
        sqlite3_finalize(st);
    }
    resp = flowd_domain_rules_json(NULL);
    flowd_response_set_ok(resp, ok);
    json_object_object_add(resp, "deleted", json_object_new_boolean(ok));
    if (!ok)
        json_object_object_add(resp, "error", json_object_new_string("not_found"));
    return resp;
}

static int flowd_domain_rules_compile_json(struct json_object *out)
{
    sqlite3_stmt *st;
    struct json_object *rules = json_object_new_array();
    int enabled_count = 0;
    int missing_refs = 0;

    st = flowd_config_prepare(
        "SELECT id,name,enabled,priority,action,domain_object,src_object,time_object,route_group,"
        "fallback,family,mark,log_event,remark,updated_at FROM flowd_domain_rules "
        "WHERE enabled=1 ORDER BY priority,id");
    if (st) {
        while (sqlite3_step(st) == SQLITE_ROW) {
            const char *action = (const char *)sqlite3_column_text(st, 4);
            const char *domain_object = (const char *)sqlite3_column_text(st, 5);
            const char *src_object = (const char *)sqlite3_column_text(st, 6);
            const char *time_object = (const char *)sqlite3_column_text(st, 7);
            const char *route_group = (const char *)sqlite3_column_text(st, 8);
            struct json_object *o = json_object_new_object();
            struct json_object *missing = json_object_new_array();
            int local_missing = 0;

            if (!flowd_object_exists_with_type(domain_object, "domain")) {
                flowd_split_rule_missing_ref(missing, "domain_object", domain_object);
                local_missing++;
            }
            if (!flowd_id_exists_in("flowd_objects", src_object)) {
                flowd_split_rule_missing_ref(missing, "src_object", src_object);
                local_missing++;
            }
            if (!flowd_id_exists_in("flowd_objects", time_object)) {
                flowd_split_rule_missing_ref(missing, "time_object", time_object);
                local_missing++;
            }
            if (action && !strcmp(action, "route") &&
                (!route_group || !route_group[0] || !flowd_id_exists_in("flowd_route_groups", route_group))) {
                flowd_split_rule_missing_ref(missing, "route_group", route_group);
                local_missing++;
            }
            json_object_object_add(o, "id", flowd_sqlite_text_json(st, 0));
            json_object_object_add(o, "name", flowd_sqlite_text_json(st, 1));
            json_object_object_add(o, "priority", json_object_new_int(sqlite3_column_int(st, 3)));
            json_object_object_add(o, "action", json_object_new_string(action ? action : ""));
            json_object_object_add(o, "domain_object", json_object_new_string(domain_object ? domain_object : ""));
            json_object_object_add(o, "src_object", json_object_new_string(src_object ? src_object : ""));
            json_object_object_add(o, "time_object", json_object_new_string(time_object ? time_object : ""));
            json_object_object_add(o, "route_group", json_object_new_string(route_group ? route_group : ""));
            json_object_object_add(o, "fallback", flowd_sqlite_text_json(st, 9));
            json_object_object_add(o, "family", flowd_sqlite_text_json(st, 10));
            json_object_object_add(o, "mark", flowd_sqlite_text_json(st, 11));
            json_object_object_add(o, "log_event", json_object_new_boolean(sqlite3_column_int(st, 12)));
            flowd_domain_rule_refs_json(o, domain_object, src_object, time_object, route_group);
            json_object_object_add(o, "runtime_kind", json_object_new_string("domain_route_rule"));
            json_object_object_add(o, "resolver_integration", json_object_new_string("pending"));
            json_object_object_add(o, "state", json_object_new_string(local_missing ? "blocked" : "planned"));
            json_object_object_add(o, "missing_refs", missing);
            json_object_object_add(o, "mutates_dataplane", json_object_new_boolean(0));
            json_object_array_add(rules, o);
            missing_refs += local_missing;
            enabled_count++;
        }
        sqlite3_finalize(st);
    }
    json_object_object_add(out, "total", json_object_new_int(flowd_count_sql("SELECT COUNT(*) FROM flowd_domain_rules")));
    json_object_object_add(out, "enabled", json_object_new_int(enabled_count));
    json_object_object_add(out, "missing_refs", json_object_new_int(missing_refs));
    json_object_object_add(out, "rules", rules);
    return missing_refs;
}

static int flowd_qos_scheduler_ok(const char *scheduler)
{
    return scheduler && (!strcmp(scheduler, "htb") || !strcmp(scheduler, "cake") ||
                         !strcmp(scheduler, "hybrid"));
}

static int flowd_qos_fairness_ok(const char *fairness)
{
    return fairness && (!strcmp(fairness, "none") || !strcmp(fairness, "per_host") ||
                        !strcmp(fairness, "per_flow") || !strcmp(fairness, "per_rule"));
}

static int flowd_qos_direction_ok(const char *direction)
{
    return direction && (!strcmp(direction, "upload") || !strcmp(direction, "download") ||
                         !strcmp(direction, "both"));
}

static int flowd_optional_token_ok(const char *s, size_t max_len)
{
    return !s || !s[0] || flowd_token_ok(s, max_len);
}

static int flowd_custom_protocol_kind_ok(const char *kind)
{
    return kind && (!strcmp(kind, "l3") || !strcmp(kind, "l4") ||
                    !strcmp(kind, "l7") || !strcmp(kind, "dpi"));
}

static struct json_object *flowd_tags_from_body(struct json_object *body)
{
    struct json_object *v = NULL;
    struct json_object *parsed = NULL;

    if (!body || !json_object_is_type(body, json_type_object))
        return json_object_new_array();
    if (!json_object_object_get_ex(body, "tags", &v) &&
        !json_object_object_get_ex(body, "tags_json", &v))
        return json_object_new_array();
    if (!v)
        return json_object_new_array();
    if (json_object_is_type(v, json_type_string)) {
        parsed = json_tokener_parse(json_object_get_string(v));
        if (parsed)
            return parsed;
    }
    return json_object_get(v);
}

static void flowd_custom_protocol_row_json(struct json_object *arr, sqlite3_stmt *st)
{
    const char *match_s = (const char *)sqlite3_column_text(st, 8);
    const char *tags_s = (const char *)sqlite3_column_text(st, 9);
    struct json_object *o = json_object_new_object();

    json_object_object_add(o, "id", flowd_sqlite_text_json(st, 0));
    json_object_object_add(o, "name", flowd_sqlite_text_json(st, 1));
    json_object_object_add(o, "enabled", json_object_new_boolean(sqlite3_column_int(st, 2)));
    json_object_object_add(o, "priority", json_object_new_int(sqlite3_column_int(st, 3)));
    json_object_object_add(o, "kind", flowd_sqlite_text_json(st, 4));
    json_object_object_add(o, "proto", flowd_sqlite_text_json(st, 5));
    json_object_object_add(o, "src_port", flowd_sqlite_text_json(st, 6));
    json_object_object_add(o, "dst_port", flowd_sqlite_text_json(st, 7));
    json_object_object_add(o, "match", flowd_json_parse_or_object(match_s));
    json_object_object_add(o, "tags", flowd_json_parse_or_array(tags_s));
    json_object_object_add(o, "remark", flowd_sqlite_text_json(st, 10));
    json_object_object_add(o, "updated_at", json_object_new_int64(sqlite3_column_int64(st, 11)));
    json_object_array_add(arr, o);
}

struct json_object *flowd_custom_protocols_json(struct json_object *body)
{
    sqlite3_stmt *st = NULL;
    struct json_object *resp = json_object_new_object();
    struct json_object *arr = json_object_new_array();
    const char *id = flowd_json_str(body, "id", "");
    const char *kind = flowd_json_str(body, "kind", "");
    int include_disabled = flowd_json_bool(body, "include_disabled", 1);
    int ok = 1;
    const char *error = "";

    if (id && id[0] && !flowd_id_ok(id))
        return flowd_error("invalid_id", "invalid custom protocol id");
    if (kind && kind[0] && !flowd_custom_protocol_kind_ok(kind))
        return flowd_error("invalid_kind", "invalid custom protocol kind");
    if (id && id[0]) {
        st = flowd_config_prepare(
            "SELECT id,name,enabled,priority,kind,proto,src_port,dst_port,match_json,tags_json,remark,updated_at "
            "FROM flowd_custom_protocols WHERE id=?1");
        if (st)
            sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    } else if (kind && kind[0]) {
        st = flowd_config_prepare(
            "SELECT id,name,enabled,priority,kind,proto,src_port,dst_port,match_json,tags_json,remark,updated_at "
            "FROM flowd_custom_protocols WHERE kind=?1 AND (?2 OR enabled=1) ORDER BY priority,id");
        if (st) {
            sqlite3_bind_text(st, 1, kind, -1, SQLITE_TRANSIENT);
            sqlite3_bind_int(st, 2, include_disabled ? 1 : 0);
        }
    } else {
        st = flowd_config_prepare(
            "SELECT id,name,enabled,priority,kind,proto,src_port,dst_port,match_json,tags_json,remark,updated_at "
            "FROM flowd_custom_protocols WHERE (?1 OR enabled=1) ORDER BY priority,id");
        if (st)
            sqlite3_bind_int(st, 1, include_disabled ? 1 : 0);
    }
    if (st) {
        ok = flowd_collect_rows(st, arr, flowd_custom_protocol_row_json, "custom protocols");
        if (!ok)
            error = "custom_protocols_unavailable";
        sqlite3_finalize(st);
    } else {
        ok = 0;
        error = "custom_protocols_unavailable";
    }
    flowd_list_total_add(resp, &ok, &error, "SELECT COUNT(*) FROM flowd_custom_protocols",
                         "custom_protocols_count_unavailable");
    json_object_object_add(resp, "ok", json_object_new_boolean(ok));
    json_object_object_add(resp, "protocols", arr);
    if (error[0])
        json_object_object_add(resp, "error", json_object_new_string(error));
    return resp;
}

static int flowd_custom_protocol_load_existing(const char *id,
                                               char *name, size_t name_len,
                                               int *enabled, int *priority,
                                               char *kind, size_t kind_len,
                                               char *proto, size_t proto_len,
                                               char *src_port, size_t src_port_len,
                                               char *dst_port, size_t dst_port_len,
                                               char *match_json, size_t match_json_len,
                                               char *tags_json, size_t tags_json_len,
                                               char *remark, size_t remark_len)
{
    sqlite3_stmt *st;
    int rc;

    if (!flowd_id_ok(id))
        return -1;
    st = flowd_config_prepare(
        "SELECT name,enabled,priority,kind,proto,src_port,dst_port,match_json,tags_json,remark "
        "FROM flowd_custom_protocols WHERE id=?1");
    if (!st)
        return -1;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) {
        snprintf(name, name_len, "%s",
                 sqlite3_column_text(st, 0) ? (const char *)sqlite3_column_text(st, 0) : "");
        if (enabled)
            *enabled = sqlite3_column_int(st, 1) ? 1 : 0;
        if (priority)
            *priority = sqlite3_column_int(st, 2);
        snprintf(kind, kind_len, "%s",
                 sqlite3_column_text(st, 3) ? (const char *)sqlite3_column_text(st, 3) : "l4");
        snprintf(proto, proto_len, "%s",
                 sqlite3_column_text(st, 4) ? (const char *)sqlite3_column_text(st, 4) : "tcp");
        snprintf(src_port, src_port_len, "%s",
                 sqlite3_column_text(st, 5) ? (const char *)sqlite3_column_text(st, 5) : "");
        snprintf(dst_port, dst_port_len, "%s",
                 sqlite3_column_text(st, 6) ? (const char *)sqlite3_column_text(st, 6) : "");
        snprintf(match_json, match_json_len, "%s",
                 sqlite3_column_text(st, 7) ? (const char *)sqlite3_column_text(st, 7) : "{}");
        snprintf(tags_json, tags_json_len, "%s",
                 sqlite3_column_text(st, 8) ? (const char *)sqlite3_column_text(st, 8) : "[]");
        snprintf(remark, remark_len, "%s",
                 sqlite3_column_text(st, 9) ? (const char *)sqlite3_column_text(st, 9) : "");
        sqlite3_finalize(st);
        return 1;
    }
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

static int flowd_custom_protocol_save_one(struct json_object *body)
{
    sqlite3_stmt *st;
    struct json_object *match = NULL;
    struct json_object *match_body = NULL;
    struct json_object *tags = NULL;
    struct json_object *tags_body = NULL;
    char generated_id[FLOWD_MAX_ID];
    char name_buf[129] = "";
    char kind_buf[32] = "l4";
    char proto_buf[32] = "tcp";
    char src_port_buf[65] = "";
    char dst_port_buf[65] = "";
    char match_json_buf[FLOWD_MAX_JSON + 1] = "{}";
    char tags_json_buf[FLOWD_MAX_JSON + 1] = "[]";
    char remark_buf[257] = "";
    const char *id, *name, *kind, *proto, *src_port, *dst_port, *remark;
    const char *match_s, *tags_s;
    int enabled, priority, ok = 0;
    int64_t now = flowd_now_s();

    if (!body || !json_object_is_type(body, json_type_object))
        return -1;
    enabled = 1;
    priority = 1000;
    id = flowd_json_str(body, "id", "");
    if (!id[0]) {
        flowd_make_id("custom-proto", generated_id, sizeof(generated_id));
        id = generated_id;
    } else {
        int existing;

        existing = flowd_custom_protocol_load_existing(id, name_buf, sizeof(name_buf),
                                                       &enabled, &priority,
                                                       kind_buf, sizeof(kind_buf),
                                                       proto_buf, sizeof(proto_buf),
                                                       src_port_buf, sizeof(src_port_buf),
                                                       dst_port_buf, sizeof(dst_port_buf),
                                                       match_json_buf, sizeof(match_json_buf),
                                                       tags_json_buf, sizeof(tags_json_buf),
                                                       remark_buf, sizeof(remark_buf));
        if (existing < 0)
            return -1;
    }
    name = flowd_json_str(body, "name", name_buf);
    enabled = flowd_json_bool(body, "enabled", enabled);
    priority = flowd_json_int(body, "priority", priority);
    kind = flowd_json_str(body, "kind", kind_buf);
    proto = flowd_json_str(body, "proto", proto_buf);
    src_port = flowd_json_str(body, "src_port", src_port_buf);
    dst_port = flowd_json_str(body, "dst_port", dst_port_buf);
    remark = flowd_json_str(body, "remark", remark_buf);
    if (json_object_object_get_ex(body, "match", &match_body) ||
        json_object_object_get_ex(body, "match_json", &match_body)) {
        match = flowd_match_from_body(body);
    } else {
        match = json_tokener_parse(match_json_buf);
        if (!match)
            match = json_object_new_object();
    }
    if (json_object_object_get_ex(body, "tags", &tags_body) ||
        json_object_object_get_ex(body, "tags_json", &tags_body)) {
        tags = flowd_tags_from_body(body);
    } else {
        tags = json_tokener_parse(tags_json_buf);
        if (!tags)
            tags = json_object_new_array();
    }
    if (!flowd_id_ok(id) || !flowd_text_ok(name, 128) || priority < 0 || priority > 1000000 ||
        !flowd_custom_protocol_kind_ok(kind) || !flowd_split_proto_ok(proto) ||
        !flowd_split_port_expr_ok(src_port) || !flowd_split_port_expr_ok(dst_port) ||
        !flowd_text_ok(remark, 256) || !json_object_is_type(tags, json_type_array) ||
        !flowd_json_fits(match, FLOWD_MAX_JSON) || !flowd_json_fits(tags, FLOWD_MAX_JSON)) {
        if (match) json_object_put(match);
        if (tags) json_object_put(tags);
        return -1;
    }
    match_s = json_object_to_json_string_ext(match, JSON_C_TO_STRING_PLAIN);
    tags_s = json_object_to_json_string_ext(tags, JSON_C_TO_STRING_PLAIN);
    if (!match_s || !tags_s) {
        json_object_put(match);
        json_object_put(tags);
        return -1;
    }
    st = flowd_config_prepare(
        "INSERT INTO flowd_custom_protocols"
        "(id,name,enabled,priority,kind,proto,src_port,dst_port,match_json,tags_json,remark,created_at,updated_at) "
        "VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?12) "
        "ON CONFLICT(id) DO UPDATE SET name=excluded.name,enabled=excluded.enabled,"
        "priority=excluded.priority,kind=excluded.kind,proto=excluded.proto,src_port=excluded.src_port,"
        "dst_port=excluded.dst_port,match_json=excluded.match_json,tags_json=excluded.tags_json,"
        "remark=excluded.remark,updated_at=excluded.updated_at");
    if (st) {
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, name, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 3, enabled ? 1 : 0);
        sqlite3_bind_int(st, 4, priority);
        sqlite3_bind_text(st, 5, kind, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 6, proto, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 7, src_port, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 8, dst_port, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 9, match_s, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 10, tags_s, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 11, remark, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 12, now);
        ok = sqlite3_step(st) == SQLITE_DONE;
        sqlite3_finalize(st);
    }
    json_object_put(match);
    json_object_put(tags);
    return ok ? 0 : -1;
}

struct json_object *flowd_custom_protocol_update(struct json_object *body)
{
    struct json_object *arr = NULL;
    int ok = 1, saved = 0, i, n;
    struct json_object *resp;

    if (!body || !json_object_is_type(body, json_type_object))
        return flowd_error("invalid_request", "custom protocol body must be an object");
    if (json_object_object_get_ex(body, "protocols", &arr) && arr &&
        json_object_is_type(arr, json_type_array)) {
        n = json_object_array_length(arr);
        for (i = 0; i < n; i++) {
            if (flowd_custom_protocol_save_one(json_object_array_get_idx(arr, i)) == 0)
                saved++;
            else
                ok = 0;
        }
    } else {
        ok = flowd_custom_protocol_save_one(body) == 0;
        saved = ok ? 1 : 0;
    }
    resp = flowd_custom_protocols_json(NULL);
    flowd_response_set_ok(resp, ok);
    json_object_object_add(resp, "saved", json_object_new_int(saved));
    if (!ok)
        json_object_object_add(resp, "error", json_object_new_string("partial_or_failed_save"));
    return resp;
}

struct json_object *flowd_custom_protocol_delete(struct json_object *body)
{
    sqlite3_stmt *st;
    const char *id = flowd_json_str(body, "id", "");
    int ok = 0;
    struct json_object *resp;

    if (!flowd_id_ok(id))
        return flowd_error("invalid_id", "invalid custom protocol id");
    st = flowd_config_prepare("DELETE FROM flowd_custom_protocols WHERE id=?1");
    if (st) {
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        ok = sqlite3_step(st) == SQLITE_DONE && sqlite3_changes(g_flowd_config_db) > 0;
        sqlite3_finalize(st);
    }
    resp = flowd_custom_protocols_json(NULL);
    flowd_response_set_ok(resp, ok);
    json_object_object_add(resp, "deleted", json_object_new_boolean(ok));
    if (!ok)
        json_object_object_add(resp, "error", json_object_new_string("not_found"));
    return resp;
}

static void flowd_custom_protocols_compile_json(struct json_object *out)
{
    sqlite3_stmt *st;
    struct json_object *compiled = json_object_new_array();
    int enabled_count = 0;

    st = flowd_config_prepare(
        "SELECT id,name,enabled,priority,kind,proto,src_port,dst_port,match_json,tags_json,remark,updated_at "
        "FROM flowd_custom_protocols WHERE enabled=1 ORDER BY priority,id");
    if (st) {
        while (sqlite3_step(st) == SQLITE_ROW) {
            const char *match_s = (const char *)sqlite3_column_text(st, 8);
            const char *tags_s = (const char *)sqlite3_column_text(st, 9);
            struct json_object *o = json_object_new_object();

            json_object_object_add(o, "id", flowd_sqlite_text_json(st, 0));
            json_object_object_add(o, "name", flowd_sqlite_text_json(st, 1));
            json_object_object_add(o, "priority", json_object_new_int(sqlite3_column_int(st, 3)));
            json_object_object_add(o, "kind", flowd_sqlite_text_json(st, 4));
            json_object_object_add(o, "proto", flowd_sqlite_text_json(st, 5));
            json_object_object_add(o, "src_port", flowd_sqlite_text_json(st, 6));
            json_object_object_add(o, "dst_port", flowd_sqlite_text_json(st, 7));
            json_object_object_add(o, "match", flowd_json_parse_or_object(match_s));
            json_object_object_add(o, "tags", flowd_json_parse_or_array(tags_s));
            json_object_object_add(o, "runtime_kind", json_object_new_string("custom_protocol_definition"));
            json_object_object_add(o, "state_store", json_object_new_string(FLOWD_DEFAULT_FLOW_DB_PATH));
            json_object_object_add(o, "state", json_object_new_string("planned"));
            json_object_object_add(o, "mutates_dataplane", json_object_new_boolean(0));
            json_object_array_add(compiled, o);
            enabled_count++;
        }
        sqlite3_finalize(st);
    }
    json_object_object_add(out, "total", json_object_new_int(flowd_count_sql("SELECT COUNT(*) FROM flowd_custom_protocols")));
    json_object_object_add(out, "enabled", json_object_new_int(enabled_count));
    json_object_object_add(out, "compiled", compiled);
}

struct json_object *flowd_qos_settings_json(void)
{
    sqlite3_stmt *st;
    struct json_object *resp = json_object_new_object();
    int ok = 0;
    int rc = SQLITE_ERROR;

    st = flowd_config_prepare(
        "SELECT enabled,scheduler,default_class,unknown_class,headroom_pct,diffserv,ack_filter,fairness,remark,updated_at "
        "FROM flowd_qos_settings WHERE id=1");
    if (st)
        rc = sqlite3_step(st);
    if (st && rc == SQLITE_ROW) {
        json_object_object_add(resp, "enabled", json_object_new_boolean(sqlite3_column_int(st, 0)));
        json_object_object_add(resp, "scheduler", flowd_sqlite_text_json(st, 1));
        json_object_object_add(resp, "default_class", flowd_sqlite_text_json(st, 2));
        json_object_object_add(resp, "unknown_class", flowd_sqlite_text_json(st, 3));
        json_object_object_add(resp, "headroom_pct", json_object_new_int(sqlite3_column_int(st, 4)));
        json_object_object_add(resp, "diffserv", json_object_new_boolean(sqlite3_column_int(st, 5)));
        json_object_object_add(resp, "ack_filter", json_object_new_boolean(sqlite3_column_int(st, 6)));
        json_object_object_add(resp, "fairness", flowd_sqlite_text_json(st, 7));
        json_object_object_add(resp, "remark", flowd_sqlite_text_json(st, 8));
        json_object_object_add(resp, "updated_at", json_object_new_int64(sqlite3_column_int64(st, 9)));
        ok = 1;
    }
    if (st)
        sqlite3_finalize(st);
    json_object_object_add(resp, "ok", json_object_new_boolean(ok));
    if (!ok)
        json_object_object_add(resp, "error", json_object_new_string(rc == SQLITE_DONE ? "qos_settings_missing" : "qos_settings_unavailable"));
    return resp;
}

struct json_object *flowd_qos_settings_update(struct json_object *body)
{
    sqlite3_stmt *st;
    char scheduler_buf[64] = "htb";
    char default_class_buf[FLOWD_MAX_ID] = "normal";
    char unknown_class_buf[FLOWD_MAX_ID] = "normal";
    char fairness_buf[64] = "per_host";
    char remark_buf[257] = "";
    const char *scheduler, *default_class, *unknown_class, *fairness, *remark;
    int enabled = 0, headroom_pct = 95, diffserv = 1, ack_filter = 0, ok = 0;
    int rc = SQLITE_ERROR;
    struct json_object *resp;

    if (!body || !json_object_is_type(body, json_type_object))
        return flowd_error("invalid_request", "qos settings body must be an object");
    st = flowd_config_prepare(
        "SELECT enabled,scheduler,default_class,unknown_class,headroom_pct,diffserv,ack_filter,fairness,remark "
        "FROM flowd_qos_settings WHERE id=1");
    if (st)
        rc = sqlite3_step(st);
    if (st && rc == SQLITE_ROW) {
        const char *s;

        enabled = sqlite3_column_int(st, 0) ? 1 : 0;
        s = (const char *)sqlite3_column_text(st, 1);
        snprintf(scheduler_buf, sizeof(scheduler_buf), "%s", s && s[0] ? s : "htb");
        s = (const char *)sqlite3_column_text(st, 2);
        snprintf(default_class_buf, sizeof(default_class_buf), "%s", s && s[0] ? s : "normal");
        s = (const char *)sqlite3_column_text(st, 3);
        snprintf(unknown_class_buf, sizeof(unknown_class_buf), "%s", s && s[0] ? s : "normal");
        headroom_pct = sqlite3_column_int(st, 4);
        diffserv = sqlite3_column_int(st, 5) ? 1 : 0;
        ack_filter = sqlite3_column_int(st, 6) ? 1 : 0;
        s = (const char *)sqlite3_column_text(st, 7);
        snprintf(fairness_buf, sizeof(fairness_buf), "%s", s && s[0] ? s : "per_host");
        s = (const char *)sqlite3_column_text(st, 8);
        snprintf(remark_buf, sizeof(remark_buf), "%s", s ? s : "");
    }
    if (st)
        sqlite3_finalize(st);
    if (rc != SQLITE_ROW)
        return flowd_error(rc == SQLITE_DONE ? "qos_settings_missing" : "qos_settings_unavailable",
                           rc == SQLITE_DONE ? "qos settings are missing" : "qos settings are unavailable");

    enabled = flowd_json_bool(body, "enabled", enabled);
    scheduler = flowd_json_str(body, "scheduler", scheduler_buf);
    default_class = flowd_json_str(body, "default_class", default_class_buf);
    unknown_class = flowd_json_str(body, "unknown_class", unknown_class_buf);
    headroom_pct = flowd_json_int(body, "headroom_pct", headroom_pct);
    diffserv = flowd_json_bool(body, "diffserv", diffserv);
    ack_filter = flowd_json_bool(body, "ack_filter", ack_filter);
    fairness = flowd_json_str(body, "fairness", fairness_buf);
    remark = flowd_json_str(body, "remark", remark_buf);
    if (!flowd_qos_scheduler_ok(scheduler) || !flowd_id_ok(default_class) ||
        !flowd_id_ok(unknown_class) || headroom_pct < 50 || headroom_pct > 100 ||
        !flowd_qos_fairness_ok(fairness) || !flowd_text_ok(remark, 256))
        return flowd_error("invalid_qos_settings", "invalid qos settings");
    st = flowd_config_prepare(
        "UPDATE flowd_qos_settings SET enabled=?1,scheduler=?2,default_class=?3,unknown_class=?4,"
        "headroom_pct=?5,diffserv=?6,ack_filter=?7,fairness=?8,remark=?9,updated_at=?10 WHERE id=1");
    if (st) {
        sqlite3_bind_int(st, 1, enabled ? 1 : 0);
        sqlite3_bind_text(st, 2, scheduler, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 3, default_class, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 4, unknown_class, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 5, headroom_pct);
        sqlite3_bind_int(st, 6, diffserv ? 1 : 0);
        sqlite3_bind_int(st, 7, ack_filter ? 1 : 0);
        sqlite3_bind_text(st, 8, fairness, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 9, remark, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 10, flowd_now_s());
        ok = sqlite3_step(st) == SQLITE_DONE;
        sqlite3_finalize(st);
    }
    resp = flowd_qos_settings_json();
    flowd_response_set_ok(resp, ok);
    json_object_object_add(resp, "saved", json_object_new_boolean(ok));
    if (!ok)
        json_object_object_add(resp, "error", json_object_new_string("save_failed"));
    return resp;
}

static void flowd_qos_class_row_json(struct json_object *arr, sqlite3_stmt *st)
{
    struct json_object *o = json_object_new_object();

    json_object_object_add(o, "id", flowd_sqlite_text_json(st, 0));
    json_object_object_add(o, "name", flowd_sqlite_text_json(st, 1));
    json_object_object_add(o, "enabled", json_object_new_boolean(sqlite3_column_int(st, 2)));
    json_object_object_add(o, "priority", json_object_new_int(sqlite3_column_int(st, 3)));
    json_object_object_add(o, "guarantee_pct", json_object_new_int(sqlite3_column_int(st, 4)));
    json_object_object_add(o, "ceiling_pct", json_object_new_int(sqlite3_column_int(st, 5)));
    json_object_object_add(o, "latency_ms", json_object_new_int(sqlite3_column_int(st, 6)));
    json_object_object_add(o, "dscp", flowd_sqlite_text_json(st, 7));
    json_object_object_add(o, "color", flowd_sqlite_text_json(st, 8));
    json_object_object_add(o, "remark", flowd_sqlite_text_json(st, 9));
    json_object_object_add(o, "updated_at", json_object_new_int64(sqlite3_column_int64(st, 10)));
    json_object_array_add(arr, o);
}

struct json_object *flowd_qos_classes_json(struct json_object *body)
{
    sqlite3_stmt *st = NULL;
    struct json_object *resp = json_object_new_object();
    struct json_object *arr = json_object_new_array();
    const char *id = flowd_json_str(body, "id", "");
    int include_disabled = flowd_json_bool(body, "include_disabled", 1);
    int ok = 1;
    const char *error = "";

    if (id && id[0] && !flowd_id_ok(id))
        return flowd_error("invalid_id", "invalid qos class id");
    if (id && id[0]) {
        st = flowd_config_prepare(
            "SELECT id,name,enabled,priority,guarantee_pct,ceiling_pct,latency_ms,dscp,color,remark,updated_at "
            "FROM flowd_qos_classes WHERE id=?1");
        if (st)
            sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    } else {
        st = flowd_config_prepare(
            "SELECT id,name,enabled,priority,guarantee_pct,ceiling_pct,latency_ms,dscp,color,remark,updated_at "
            "FROM flowd_qos_classes WHERE (?1 OR enabled=1) ORDER BY priority,id");
        if (st)
            sqlite3_bind_int(st, 1, include_disabled ? 1 : 0);
    }
    if (st) {
        ok = flowd_collect_rows(st, arr, flowd_qos_class_row_json, "qos classes");
        if (!ok)
            error = "qos_classes_unavailable";
        sqlite3_finalize(st);
    } else {
        ok = 0;
        error = "qos_classes_unavailable";
    }
    flowd_list_total_add(resp, &ok, &error, "SELECT COUNT(*) FROM flowd_qos_classes",
                         "qos_classes_count_unavailable");
    json_object_object_add(resp, "ok", json_object_new_boolean(ok));
    json_object_object_add(resp, "classes", arr);
    if (error[0])
        json_object_object_add(resp, "error", json_object_new_string(error));
    return resp;
}

static int flowd_qos_class_load_existing(const char *id,
                                         char *name, size_t name_len,
                                         int *enabled, int *priority,
                                         int *guarantee_pct, int *ceiling_pct,
                                         int *latency_ms,
                                         char *dscp, size_t dscp_len,
                                         char *color, size_t color_len,
                                         char *remark, size_t remark_len)
{
    sqlite3_stmt *st;
    int rc;

    if (!flowd_id_ok(id))
        return -1;
    st = flowd_config_prepare(
        "SELECT name,enabled,priority,guarantee_pct,ceiling_pct,latency_ms,dscp,color,remark "
        "FROM flowd_qos_classes WHERE id=?1");
    if (!st)
        return -1;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) {
        snprintf(name, name_len, "%s",
                 sqlite3_column_text(st, 0) ? (const char *)sqlite3_column_text(st, 0) : "");
        if (enabled)
            *enabled = sqlite3_column_int(st, 1) ? 1 : 0;
        if (priority)
            *priority = sqlite3_column_int(st, 2);
        if (guarantee_pct)
            *guarantee_pct = sqlite3_column_int(st, 3);
        if (ceiling_pct)
            *ceiling_pct = sqlite3_column_int(st, 4);
        if (latency_ms)
            *latency_ms = sqlite3_column_int(st, 5);
        snprintf(dscp, dscp_len, "%s",
                 sqlite3_column_text(st, 6) ? (const char *)sqlite3_column_text(st, 6) : "");
        snprintf(color, color_len, "%s",
                 sqlite3_column_text(st, 7) ? (const char *)sqlite3_column_text(st, 7) : "");
        snprintf(remark, remark_len, "%s",
                 sqlite3_column_text(st, 8) ? (const char *)sqlite3_column_text(st, 8) : "");
        sqlite3_finalize(st);
        return 1;
    }
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

static int flowd_qos_class_save_one(struct json_object *body)
{
    sqlite3_stmt *st;
    char generated_id[FLOWD_MAX_ID];
    char name_buf[129] = "";
    char dscp_buf[33] = "";
    char color_buf[33] = "";
    char remark_buf[257] = "";
    const char *id, *name, *dscp, *color, *remark;
    int enabled, priority, guarantee_pct, ceiling_pct, latency_ms, ok = 0;
    int64_t now = flowd_now_s();

    if (!body || !json_object_is_type(body, json_type_object))
        return -1;
    enabled = 1;
    priority = 100;
    guarantee_pct = 0;
    ceiling_pct = 100;
    latency_ms = 0;
    id = flowd_json_str(body, "id", "");
    if (!id[0]) {
        flowd_make_id("qos-class", generated_id, sizeof(generated_id));
        id = generated_id;
    } else {
        int existing;

        existing = flowd_qos_class_load_existing(id, name_buf, sizeof(name_buf),
                                                 &enabled, &priority,
                                                 &guarantee_pct, &ceiling_pct,
                                                 &latency_ms, dscp_buf, sizeof(dscp_buf),
                                                 color_buf, sizeof(color_buf),
                                                 remark_buf, sizeof(remark_buf));
        if (existing < 0)
            return -1;
    }
    name = flowd_json_str(body, "name", name_buf);
    enabled = flowd_json_bool(body, "enabled", enabled);
    priority = flowd_json_int(body, "priority", priority);
    guarantee_pct = flowd_json_int(body, "guarantee_pct", guarantee_pct);
    ceiling_pct = flowd_json_int(body, "ceiling_pct", ceiling_pct);
    latency_ms = flowd_json_int(body, "latency_ms", latency_ms);
    dscp = flowd_json_str(body, "dscp", dscp_buf);
    color = flowd_json_str(body, "color", color_buf);
    remark = flowd_json_str(body, "remark", remark_buf);
    if (!flowd_id_ok(id) || !flowd_text_ok(name, 128) || priority < 0 || priority > 100000 ||
        guarantee_pct < 0 || guarantee_pct > 100 || ceiling_pct < 1 || ceiling_pct > 100 ||
        ceiling_pct < guarantee_pct || latency_ms < 0 || latency_ms > 600000 ||
        !flowd_optional_token_ok(dscp, 32) || !flowd_text_ok(color, 32) ||
        !flowd_text_ok(remark, 256))
        return -1;
    st = flowd_config_prepare(
        "INSERT INTO flowd_qos_classes"
        "(id,name,enabled,priority,guarantee_pct,ceiling_pct,latency_ms,dscp,color,remark,created_at,updated_at) "
        "VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?11) "
        "ON CONFLICT(id) DO UPDATE SET name=excluded.name,enabled=excluded.enabled,"
        "priority=excluded.priority,guarantee_pct=excluded.guarantee_pct,"
        "ceiling_pct=excluded.ceiling_pct,latency_ms=excluded.latency_ms,dscp=excluded.dscp,"
        "color=excluded.color,remark=excluded.remark,updated_at=excluded.updated_at");
    if (st) {
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, name, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 3, enabled ? 1 : 0);
        sqlite3_bind_int(st, 4, priority);
        sqlite3_bind_int(st, 5, guarantee_pct);
        sqlite3_bind_int(st, 6, ceiling_pct);
        sqlite3_bind_int(st, 7, latency_ms);
        sqlite3_bind_text(st, 8, dscp, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 9, color, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 10, remark, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 11, now);
        ok = sqlite3_step(st) == SQLITE_DONE;
        sqlite3_finalize(st);
    }
    return ok ? 0 : -1;
}

struct json_object *flowd_qos_class_update(struct json_object *body)
{
    struct json_object *arr = NULL;
    int ok = 1, saved = 0, i, n;
    struct json_object *resp;

    if (!body || !json_object_is_type(body, json_type_object))
        return flowd_error("invalid_request", "qos class body must be an object");
    if (json_object_object_get_ex(body, "classes", &arr) && arr &&
        json_object_is_type(arr, json_type_array)) {
        n = json_object_array_length(arr);
        for (i = 0; i < n; i++) {
            if (flowd_qos_class_save_one(json_object_array_get_idx(arr, i)) == 0)
                saved++;
            else
                ok = 0;
        }
    } else {
        ok = flowd_qos_class_save_one(body) == 0;
        saved = ok ? 1 : 0;
    }
    resp = flowd_qos_classes_json(NULL);
    flowd_response_set_ok(resp, ok);
    json_object_object_add(resp, "saved", json_object_new_int(saved));
    if (!ok)
        json_object_object_add(resp, "error", json_object_new_string("partial_or_failed_save"));
    return resp;
}

struct json_object *flowd_qos_class_delete(struct json_object *body)
{
    sqlite3_stmt *st;
    const char *id = flowd_json_str(body, "id", "");
    int ok = 0;
    struct json_object *resp;

    if (!flowd_id_ok(id))
        return flowd_error("invalid_id", "invalid qos class id");
    st = flowd_config_prepare("DELETE FROM flowd_qos_classes WHERE id=?1");
    if (st) {
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        ok = sqlite3_step(st) == SQLITE_DONE && sqlite3_changes(g_flowd_config_db) > 0;
        sqlite3_finalize(st);
    }
    resp = flowd_qos_classes_json(NULL);
    flowd_response_set_ok(resp, ok);
    json_object_object_add(resp, "deleted", json_object_new_boolean(ok));
    if (!ok)
        json_object_object_add(resp, "error", json_object_new_string("not_found"));
    return resp;
}

static void flowd_qos_rule_refs_json(struct json_object *o,
                                     const char *class_id,
                                     const char *src_object,
                                     const char *dst_object,
                                     const char *app_object,
                                     const char *service_object,
                                     const char *time_object)
{
    struct json_object *refs = json_object_new_object();

    json_object_object_add(refs, "class_id", json_object_new_string(class_id ? class_id : ""));
    json_object_object_add(refs, "src_object", json_object_new_string(src_object ? src_object : ""));
    json_object_object_add(refs, "dst_object", json_object_new_string(dst_object ? dst_object : ""));
    json_object_object_add(refs, "app_object", json_object_new_string(app_object ? app_object : ""));
    json_object_object_add(refs, "service_object", json_object_new_string(service_object ? service_object : ""));
    json_object_object_add(refs, "time_object", json_object_new_string(time_object ? time_object : ""));
    json_object_object_add(o, "refs", refs);
}

static void flowd_qos_rule_row_json(struct json_object *arr, sqlite3_stmt *st)
{
    const char *class_id = (const char *)sqlite3_column_text(st, 4);
    const char *src_object = (const char *)sqlite3_column_text(st, 8);
    const char *dst_object = (const char *)sqlite3_column_text(st, 9);
    const char *app_object = (const char *)sqlite3_column_text(st, 10);
    const char *service_object = (const char *)sqlite3_column_text(st, 11);
    const char *time_object = (const char *)sqlite3_column_text(st, 12);
    const char *match_s = (const char *)sqlite3_column_text(st, 16);
    struct json_object *o = json_object_new_object();

    json_object_object_add(o, "id", flowd_sqlite_text_json(st, 0));
    json_object_object_add(o, "name", flowd_sqlite_text_json(st, 1));
    json_object_object_add(o, "enabled", json_object_new_boolean(sqlite3_column_int(st, 2)));
    json_object_object_add(o, "priority", json_object_new_int(sqlite3_column_int(st, 3)));
    json_object_object_add(o, "class_id", json_object_new_string(class_id ? class_id : ""));
    json_object_object_add(o, "direction", flowd_sqlite_text_json(st, 5));
    json_object_object_add(o, "family", flowd_sqlite_text_json(st, 6));
    json_object_object_add(o, "interface", flowd_sqlite_text_json(st, 7));
    flowd_qos_rule_refs_json(o, class_id, src_object, dst_object, app_object,
                             service_object, time_object);
    json_object_object_add(o, "rate_kbps", json_object_new_int(sqlite3_column_int(st, 13)));
    json_object_object_add(o, "ceil_kbps", json_object_new_int(sqlite3_column_int(st, 14)));
    json_object_object_add(o, "per_host", json_object_new_boolean(sqlite3_column_int(st, 15)));
    json_object_object_add(o, "match", flowd_json_parse_or_object(match_s));
    json_object_object_add(o, "remark", flowd_sqlite_text_json(st, 17));
    json_object_object_add(o, "updated_at", json_object_new_int64(sqlite3_column_int64(st, 18)));
    json_object_array_add(arr, o);
}

struct json_object *flowd_qos_rules_json(struct json_object *body)
{
    sqlite3_stmt *st = NULL;
    struct json_object *resp = json_object_new_object();
    struct json_object *arr = json_object_new_array();
    const char *id = flowd_json_str(body, "id", "");
    int include_disabled = flowd_json_bool(body, "include_disabled", 1);
    int ok = 1;
    const char *error = "";

    if (id && id[0] && !flowd_id_ok(id))
        return flowd_error("invalid_id", "invalid qos rule id");
    if (id && id[0]) {
        st = flowd_config_prepare(
            "SELECT id,name,enabled,priority,class_id,direction,family,interface,src_object,dst_object,"
            "app_object,service_object,time_object,rate_kbps,ceil_kbps,per_host,match_json,remark,updated_at "
            "FROM flowd_qos_rules WHERE id=?1");
        if (st)
            sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    } else {
        st = flowd_config_prepare(
            "SELECT id,name,enabled,priority,class_id,direction,family,interface,src_object,dst_object,"
            "app_object,service_object,time_object,rate_kbps,ceil_kbps,per_host,match_json,remark,updated_at "
            "FROM flowd_qos_rules WHERE (?1 OR enabled=1) ORDER BY priority,id");
        if (st)
            sqlite3_bind_int(st, 1, include_disabled ? 1 : 0);
    }
    if (st) {
        ok = flowd_collect_rows(st, arr, flowd_qos_rule_row_json, "qos rules");
        if (!ok)
            error = "qos_rules_unavailable";
        sqlite3_finalize(st);
    } else {
        ok = 0;
        error = "qos_rules_unavailable";
    }
    flowd_list_total_add(resp, &ok, &error, "SELECT COUNT(*) FROM flowd_qos_rules",
                         "qos_rules_count_unavailable");
    json_object_object_add(resp, "ok", json_object_new_boolean(ok));
    json_object_object_add(resp, "rules", arr);
    if (error[0])
        json_object_object_add(resp, "error", json_object_new_string(error));
    return resp;
}

static int flowd_qos_rule_load_existing(const char *id,
                                        char *name, size_t name_len,
                                        int *enabled, int *priority,
                                        char *class_id, size_t class_id_len,
                                        char *direction, size_t direction_len,
                                        char *family, size_t family_len,
                                        char *interface, size_t interface_len,
                                        char *src_object, size_t src_object_len,
                                        char *dst_object, size_t dst_object_len,
                                        char *app_object, size_t app_object_len,
                                        char *service_object, size_t service_object_len,
                                        char *time_object, size_t time_object_len,
                                        int *rate_kbps, int *ceil_kbps,
                                        int *per_host,
                                        char *match_json, size_t match_json_len,
                                        char *remark, size_t remark_len)
{
    sqlite3_stmt *st;
    int rc;

    if (!flowd_id_ok(id))
        return -1;
    st = flowd_config_prepare(
        "SELECT name,enabled,priority,class_id,direction,family,interface,src_object,dst_object,"
        "app_object,service_object,time_object,rate_kbps,ceil_kbps,per_host,match_json,remark "
        "FROM flowd_qos_rules WHERE id=?1");
    if (!st)
        return -1;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) {
        snprintf(name, name_len, "%s",
                 sqlite3_column_text(st, 0) ? (const char *)sqlite3_column_text(st, 0) : "");
        if (enabled)
            *enabled = sqlite3_column_int(st, 1) ? 1 : 0;
        if (priority)
            *priority = sqlite3_column_int(st, 2);
        snprintf(class_id, class_id_len, "%s",
                 sqlite3_column_text(st, 3) ? (const char *)sqlite3_column_text(st, 3) : "normal");
        snprintf(direction, direction_len, "%s",
                 sqlite3_column_text(st, 4) ? (const char *)sqlite3_column_text(st, 4) : "both");
        snprintf(family, family_len, "%s",
                 sqlite3_column_text(st, 5) ? (const char *)sqlite3_column_text(st, 5) : "both");
        snprintf(interface, interface_len, "%s",
                 sqlite3_column_text(st, 6) ? (const char *)sqlite3_column_text(st, 6) : "");
        snprintf(src_object, src_object_len, "%s",
                 sqlite3_column_text(st, 7) ? (const char *)sqlite3_column_text(st, 7) : "");
        snprintf(dst_object, dst_object_len, "%s",
                 sqlite3_column_text(st, 8) ? (const char *)sqlite3_column_text(st, 8) : "");
        snprintf(app_object, app_object_len, "%s",
                 sqlite3_column_text(st, 9) ? (const char *)sqlite3_column_text(st, 9) : "");
        snprintf(service_object, service_object_len, "%s",
                 sqlite3_column_text(st, 10) ? (const char *)sqlite3_column_text(st, 10) : "");
        snprintf(time_object, time_object_len, "%s",
                 sqlite3_column_text(st, 11) ? (const char *)sqlite3_column_text(st, 11) : "");
        if (rate_kbps)
            *rate_kbps = sqlite3_column_int(st, 12);
        if (ceil_kbps)
            *ceil_kbps = sqlite3_column_int(st, 13);
        if (per_host)
            *per_host = sqlite3_column_int(st, 14) ? 1 : 0;
        snprintf(match_json, match_json_len, "%s",
                 sqlite3_column_text(st, 15) ? (const char *)sqlite3_column_text(st, 15) : "{}");
        snprintf(remark, remark_len, "%s",
                 sqlite3_column_text(st, 16) ? (const char *)sqlite3_column_text(st, 16) : "");
        sqlite3_finalize(st);
        return 1;
    }
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

static int flowd_qos_rule_save_one(struct json_object *body)
{
    sqlite3_stmt *st;
    struct json_object *match = NULL;
    struct json_object *match_body = NULL;
    char generated_id[FLOWD_MAX_ID];
    char name_buf[129] = "";
    char class_id_buf[FLOWD_MAX_ID] = "normal";
    char direction_buf[16] = "both";
    char family_buf[16] = "both";
    char interface_buf[65] = "";
    char src_object_buf[FLOWD_MAX_ID] = "";
    char dst_object_buf[FLOWD_MAX_ID] = "";
    char app_object_buf[FLOWD_MAX_ID] = "";
    char service_object_buf[FLOWD_MAX_ID] = "";
    char time_object_buf[FLOWD_MAX_ID] = "";
    char match_json_buf[FLOWD_MAX_JSON + 1] = "{}";
    char remark_buf[257] = "";
    const char *id, *name, *class_id, *direction, *family, *family_norm, *interface;
    const char *src_object, *dst_object, *app_object, *service_object, *time_object;
    const char *remark, *match_s;
    int enabled, priority, rate_kbps, ceil_kbps, per_host, ok = 0;
    int64_t now = flowd_now_s();

    if (!body || !json_object_is_type(body, json_type_object))
        return -1;
    enabled = 1;
    priority = 1000;
    rate_kbps = 0;
    ceil_kbps = 0;
    per_host = 0;
    id = flowd_json_str(body, "id", "");
    if (!id[0]) {
        flowd_make_id("qos-rule", generated_id, sizeof(generated_id));
        id = generated_id;
    } else {
        int existing;

        existing = flowd_qos_rule_load_existing(id, name_buf, sizeof(name_buf),
                                                &enabled, &priority,
                                                class_id_buf, sizeof(class_id_buf),
                                                direction_buf, sizeof(direction_buf),
                                                family_buf, sizeof(family_buf),
                                                interface_buf, sizeof(interface_buf),
                                                src_object_buf, sizeof(src_object_buf),
                                                dst_object_buf, sizeof(dst_object_buf),
                                                app_object_buf, sizeof(app_object_buf),
                                                service_object_buf, sizeof(service_object_buf),
                                                time_object_buf, sizeof(time_object_buf),
                                                &rate_kbps, &ceil_kbps, &per_host,
                                                match_json_buf, sizeof(match_json_buf),
                                                remark_buf, sizeof(remark_buf));
        if (existing < 0)
            return -1;
    }
    name = flowd_json_str(body, "name", name_buf);
    enabled = flowd_json_bool(body, "enabled", enabled);
    priority = flowd_json_int(body, "priority", priority);
    class_id = flowd_json_str(body, "class_id", class_id_buf);
    direction = flowd_json_str(body, "direction", direction_buf);
    family = flowd_json_str(body, "family", family_buf);
    family_norm = flowd_policy_family(family);
    interface = flowd_json_str(body, "interface", interface_buf);
    src_object = flowd_json_str(body, "src_object", src_object_buf);
    dst_object = flowd_json_str(body, "dst_object", dst_object_buf);
    app_object = flowd_json_str(body, "app_object", app_object_buf);
    service_object = flowd_json_str(body, "service_object", service_object_buf);
    time_object = flowd_json_str(body, "time_object", time_object_buf);
    rate_kbps = flowd_json_int(body, "rate_kbps", rate_kbps);
    ceil_kbps = flowd_json_int(body, "ceil_kbps", ceil_kbps);
    per_host = flowd_json_bool(body, "per_host", per_host);
    remark = flowd_json_str(body, "remark", remark_buf);
    if (json_object_object_get_ex(body, "match", &match_body) ||
        json_object_object_get_ex(body, "match_json", &match_body)) {
        match = flowd_match_from_body(body);
    } else {
        match = json_tokener_parse(match_json_buf);
        if (!match)
            match = json_object_new_object();
    }
    if (!flowd_id_ok(id) || !flowd_text_ok(name, 128) || priority < 0 || priority > 1000000 ||
        !flowd_id_ok(class_id) || !flowd_qos_direction_ok(direction) || !family_norm ||
        !flowd_optional_token_ok(interface, 64) || !flowd_optional_id_ok(src_object) ||
        !flowd_optional_id_ok(dst_object) || !flowd_optional_id_ok(app_object) ||
        !flowd_optional_id_ok(service_object) || !flowd_optional_id_ok(time_object) ||
        rate_kbps < 0 || rate_kbps > 100000000 || ceil_kbps < 0 || ceil_kbps > 100000000 ||
        (rate_kbps > 0 && ceil_kbps > 0 && ceil_kbps < rate_kbps) ||
        !flowd_text_ok(remark, 256) || !match || !json_object_is_type(match, json_type_object) ||
        !flowd_json_fits(match, FLOWD_MAX_JSON)) {
        if (match)
            json_object_put(match);
        return -1;
    }
    match_s = json_object_to_json_string_ext(match, JSON_C_TO_STRING_PLAIN);
    if (!match_s) {
        json_object_put(match);
        return -1;
    }
    st = flowd_config_prepare(
        "INSERT INTO flowd_qos_rules"
        "(id,name,enabled,priority,class_id,direction,family,interface,src_object,dst_object,"
        "app_object,service_object,time_object,rate_kbps,ceil_kbps,per_host,match_json,remark,created_at,updated_at) "
        "VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?19) "
        "ON CONFLICT(id) DO UPDATE SET name=excluded.name,enabled=excluded.enabled,"
        "priority=excluded.priority,class_id=excluded.class_id,direction=excluded.direction,"
        "family=excluded.family,interface=excluded.interface,src_object=excluded.src_object,"
        "dst_object=excluded.dst_object,app_object=excluded.app_object,service_object=excluded.service_object,"
        "time_object=excluded.time_object,rate_kbps=excluded.rate_kbps,ceil_kbps=excluded.ceil_kbps,"
        "per_host=excluded.per_host,match_json=excluded.match_json,remark=excluded.remark,"
        "updated_at=excluded.updated_at");
    if (st) {
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, name, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 3, enabled ? 1 : 0);
        sqlite3_bind_int(st, 4, priority);
        sqlite3_bind_text(st, 5, class_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 6, direction, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 7, family_norm, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 8, interface, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 9, src_object, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 10, dst_object, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 11, app_object, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 12, service_object, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 13, time_object, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 14, rate_kbps);
        sqlite3_bind_int(st, 15, ceil_kbps);
        sqlite3_bind_int(st, 16, per_host ? 1 : 0);
        sqlite3_bind_text(st, 17, match_s, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 18, remark, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 19, now);
        ok = sqlite3_step(st) == SQLITE_DONE;
        sqlite3_finalize(st);
    }
    json_object_put(match);
    return ok ? 0 : -1;
}

struct json_object *flowd_qos_rule_update(struct json_object *body)
{
    struct json_object *arr = NULL;
    int ok = 1, saved = 0, i, n;
    struct json_object *resp;

    if (!body || !json_object_is_type(body, json_type_object))
        return flowd_error("invalid_request", "qos rule body must be an object");
    if (json_object_object_get_ex(body, "rules", &arr) && arr &&
        json_object_is_type(arr, json_type_array)) {
        n = json_object_array_length(arr);
        for (i = 0; i < n; i++) {
            if (flowd_qos_rule_save_one(json_object_array_get_idx(arr, i)) == 0)
                saved++;
            else
                ok = 0;
        }
    } else {
        ok = flowd_qos_rule_save_one(body) == 0;
        saved = ok ? 1 : 0;
    }
    resp = flowd_qos_rules_json(NULL);
    flowd_response_set_ok(resp, ok);
    json_object_object_add(resp, "saved", json_object_new_int(saved));
    if (!ok)
        json_object_object_add(resp, "error", json_object_new_string("partial_or_failed_save"));
    return resp;
}

struct json_object *flowd_qos_rule_delete(struct json_object *body)
{
    sqlite3_stmt *st;
    const char *id = flowd_json_str(body, "id", "");
    int ok = 0;
    struct json_object *resp;

    if (!flowd_id_ok(id))
        return flowd_error("invalid_id", "invalid qos rule id");
    st = flowd_config_prepare("DELETE FROM flowd_qos_rules WHERE id=?1");
    if (st) {
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        ok = sqlite3_step(st) == SQLITE_DONE && sqlite3_changes(g_flowd_config_db) > 0;
        sqlite3_finalize(st);
    }
    resp = flowd_qos_rules_json(NULL);
    flowd_response_set_ok(resp, ok);
    json_object_object_add(resp, "deleted", json_object_new_boolean(ok));
    if (!ok)
        json_object_object_add(resp, "error", json_object_new_string("not_found"));
    return resp;
}

static void flowd_qos_compile_classes_json(struct json_object *out)
{
    sqlite3_stmt *st;
    struct json_object *classes = json_object_new_array();
    int enabled_count = 0;

    st = flowd_config_prepare(
        "SELECT id,name,enabled,priority,guarantee_pct,ceiling_pct,latency_ms,dscp,color,remark,updated_at "
        "FROM flowd_qos_classes WHERE enabled=1 ORDER BY priority,id");
    if (st) {
        while (sqlite3_step(st) == SQLITE_ROW) {
            struct json_object *o = json_object_new_object();

            json_object_object_add(o, "id", flowd_sqlite_text_json(st, 0));
            json_object_object_add(o, "name", flowd_sqlite_text_json(st, 1));
            json_object_object_add(o, "priority", json_object_new_int(sqlite3_column_int(st, 3)));
            json_object_object_add(o, "guarantee_pct", json_object_new_int(sqlite3_column_int(st, 4)));
            json_object_object_add(o, "ceiling_pct", json_object_new_int(sqlite3_column_int(st, 5)));
            json_object_object_add(o, "latency_ms", json_object_new_int(sqlite3_column_int(st, 6)));
            json_object_object_add(o, "dscp", flowd_sqlite_text_json(st, 7));
            json_object_object_add(o, "runtime_kind", json_object_new_string("tc_class"));
            json_object_object_add(o, "state", json_object_new_string("planned"));
            json_object_object_add(o, "mutates_dataplane", json_object_new_boolean(0));
            json_object_array_add(classes, o);
            enabled_count++;
        }
        sqlite3_finalize(st);
    }
    json_object_object_add(out, "class_total", json_object_new_int(flowd_count_sql("SELECT COUNT(*) FROM flowd_qos_classes")));
    json_object_object_add(out, "class_enabled", json_object_new_int(enabled_count));
    json_object_object_add(out, "classes", classes);
}

static int flowd_qos_compile_rules_json(struct json_object *out)
{
    sqlite3_stmt *st;
    struct json_object *rules = json_object_new_array();
    int enabled_count = 0;
    int missing_refs = 0;

    st = flowd_config_prepare(
        "SELECT id,name,enabled,priority,class_id,direction,family,interface,src_object,dst_object,"
        "app_object,service_object,time_object,rate_kbps,ceil_kbps,per_host,match_json,remark,updated_at "
        "FROM flowd_qos_rules WHERE enabled=1 ORDER BY priority,id");
    if (st) {
        while (sqlite3_step(st) == SQLITE_ROW) {
            const char *class_id = (const char *)sqlite3_column_text(st, 4);
            const char *src_object = (const char *)sqlite3_column_text(st, 8);
            const char *dst_object = (const char *)sqlite3_column_text(st, 9);
            const char *app_object = (const char *)sqlite3_column_text(st, 10);
            const char *service_object = (const char *)sqlite3_column_text(st, 11);
            const char *time_object = (const char *)sqlite3_column_text(st, 12);
            const char *match_s = (const char *)sqlite3_column_text(st, 16);
            struct json_object *o = json_object_new_object();
            struct json_object *missing = json_object_new_array();
            int local_missing = 0;

            if (!class_id || !class_id[0] || !flowd_id_exists_in("flowd_qos_classes", class_id)) {
                flowd_split_rule_missing_ref(missing, "class_id", class_id);
                local_missing++;
            }
            if (!flowd_id_exists_in("flowd_objects", src_object)) {
                flowd_split_rule_missing_ref(missing, "src_object", src_object);
                local_missing++;
            }
            if (!flowd_id_exists_in("flowd_objects", dst_object)) {
                flowd_split_rule_missing_ref(missing, "dst_object", dst_object);
                local_missing++;
            }
            if (!flowd_id_exists_in("flowd_objects", app_object)) {
                flowd_split_rule_missing_ref(missing, "app_object", app_object);
                local_missing++;
            }
            if (!flowd_id_exists_in("flowd_objects", service_object)) {
                flowd_split_rule_missing_ref(missing, "service_object", service_object);
                local_missing++;
            }
            if (!flowd_id_exists_in("flowd_objects", time_object)) {
                flowd_split_rule_missing_ref(missing, "time_object", time_object);
                local_missing++;
            }
            json_object_object_add(o, "id", flowd_sqlite_text_json(st, 0));
            json_object_object_add(o, "name", flowd_sqlite_text_json(st, 1));
            json_object_object_add(o, "priority", json_object_new_int(sqlite3_column_int(st, 3)));
            json_object_object_add(o, "class_id", json_object_new_string(class_id ? class_id : ""));
            json_object_object_add(o, "direction", flowd_sqlite_text_json(st, 5));
            json_object_object_add(o, "family", flowd_sqlite_text_json(st, 6));
            json_object_object_add(o, "interface", flowd_sqlite_text_json(st, 7));
            flowd_qos_rule_refs_json(o, class_id, src_object, dst_object, app_object,
                                     service_object, time_object);
            json_object_object_add(o, "rate_kbps", json_object_new_int(sqlite3_column_int(st, 13)));
            json_object_object_add(o, "ceil_kbps", json_object_new_int(sqlite3_column_int(st, 14)));
            json_object_object_add(o, "per_host", json_object_new_boolean(sqlite3_column_int(st, 15)));
            json_object_object_add(o, "match", flowd_json_parse_or_object(match_s));
            json_object_object_add(o, "runtime_kind", json_object_new_string("tc_filter_rule"));
            json_object_object_add(o, "state", json_object_new_string(local_missing ? "blocked" : "planned"));
            json_object_object_add(o, "missing_refs", missing);
            json_object_object_add(o, "mutates_dataplane", json_object_new_boolean(0));
            json_object_array_add(rules, o);
            missing_refs += local_missing;
            enabled_count++;
        }
        sqlite3_finalize(st);
    }
    json_object_object_add(out, "rule_total", json_object_new_int(flowd_count_sql("SELECT COUNT(*) FROM flowd_qos_rules")));
    json_object_object_add(out, "rule_enabled", json_object_new_int(enabled_count));
    json_object_object_add(out, "rule_missing_refs", json_object_new_int(missing_refs));
    json_object_object_add(out, "rules", rules);
    return missing_refs;
}

static int flowd_qos_settings_refs_json(struct json_object *out, struct json_object *settings)
{
    struct json_object *missing = json_object_new_array();
    const char *default_class;
    const char *unknown_class;
    int local_missing = 0;

    if (!settings || !flowd_json_bool(settings, "enabled", 0)) {
        json_object_object_add(out, "settings_missing_refs", missing);
        return 0;
    }
    default_class = flowd_json_str(settings, "default_class", "normal");
    unknown_class = flowd_json_str(settings, "unknown_class", "normal");
    if (!flowd_id_exists_in("flowd_qos_classes", default_class)) {
        flowd_split_rule_missing_ref(missing, "default_class", default_class);
        local_missing++;
    }
    if (!flowd_id_exists_in("flowd_qos_classes", unknown_class)) {
        flowd_split_rule_missing_ref(missing, "unknown_class", unknown_class);
        local_missing++;
    }
    json_object_object_add(out, "settings_missing_refs", missing);
    return local_missing;
}

static int flowd_qos_compile_json(struct json_object *out)
{
    struct json_object *settings = flowd_qos_settings_json();
    int settings_missing_refs;
    int rule_missing_refs;

    settings_missing_refs = flowd_qos_settings_refs_json(out, settings);
    json_object_object_add(out, "settings", settings);
    flowd_qos_compile_classes_json(out);
    rule_missing_refs = flowd_qos_compile_rules_json(out);
    json_object_object_add(out, "missing_refs", json_object_new_int(settings_missing_refs + rule_missing_refs));
    return settings_missing_refs + rule_missing_refs;
}

static void flowd_smart_qos_category_row_json(struct json_object *arr, sqlite3_stmt *st)
{
    struct json_object *o = json_object_new_object();

    json_object_object_add(o, "id", flowd_sqlite_text_json(st, 0));
    json_object_object_add(o, "name", flowd_sqlite_text_json(st, 1));
    json_object_object_add(o, "enabled", json_object_new_boolean(sqlite3_column_int(st, 2)));
    json_object_object_add(o, "category", flowd_sqlite_text_json(st, 3));
    json_object_object_add(o, "priority", json_object_new_int(sqlite3_column_int(st, 4)));
    json_object_object_add(o, "qos_class", flowd_sqlite_text_json(st, 5));
    json_object_object_add(o, "latency_target_ms", json_object_new_int(sqlite3_column_int(st, 6)));
    json_object_object_add(o, "remark", flowd_sqlite_text_json(st, 7));
    json_object_object_add(o, "updated_at", json_object_new_int64(sqlite3_column_int64(st, 8)));
    json_object_array_add(arr, o);
}

static int flowd_smart_qos_id_for_category(const char *category, char *out, size_t out_len)
{
    sqlite3_stmt *st;
    const char *id;
    int found = 0;

    if (!flowd_token_ok(category, 64) || !out || out_len == 0)
        return 0;
    st = flowd_config_prepare("SELECT id FROM flowd_smart_qos_categories WHERE category=?1 LIMIT 1");
    if (!st)
        return 0;
    sqlite3_bind_text(st, 1, category, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW) {
        id = (const char *)sqlite3_column_text(st, 0);
        if (id && id[0]) {
            snprintf(out, out_len, "%s", id);
            found = 1;
        }
    }
    sqlite3_finalize(st);
    return found;
}

struct json_object *flowd_smart_qos_categories_json(struct json_object *body)
{
    sqlite3_stmt *st = NULL;
    struct json_object *resp = json_object_new_object();
    struct json_object *arr = json_object_new_array();
    const char *id = flowd_json_str(body, "id", "");
    const char *category = flowd_json_str(body, "category", "");
    int include_disabled = flowd_json_bool(body, "include_disabled", 1);
    int ok = 1;
    const char *error = "";

    if (id && id[0] && !flowd_id_ok(id))
        return flowd_error("invalid_id", "invalid smart qos category id");
    if (category && category[0] && !flowd_token_ok(category, 64))
        return flowd_error("invalid_category", "invalid smart qos category");
    if (id && id[0]) {
        st = flowd_config_prepare(
            "SELECT id,name,enabled,category,priority,qos_class,latency_target_ms,remark,updated_at "
            "FROM flowd_smart_qos_categories WHERE id=?1");
        if (st)
            sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    } else if (category && category[0]) {
        st = flowd_config_prepare(
            "SELECT id,name,enabled,category,priority,qos_class,latency_target_ms,remark,updated_at "
            "FROM flowd_smart_qos_categories WHERE category=?1 AND (?2 OR enabled=1) ORDER BY priority,category");
        if (st) {
            sqlite3_bind_text(st, 1, category, -1, SQLITE_TRANSIENT);
            sqlite3_bind_int(st, 2, include_disabled ? 1 : 0);
        }
    } else {
        st = flowd_config_prepare(
            "SELECT id,name,enabled,category,priority,qos_class,latency_target_ms,remark,updated_at "
            "FROM flowd_smart_qos_categories WHERE (?1 OR enabled=1) ORDER BY priority,category");
        if (st)
            sqlite3_bind_int(st, 1, include_disabled ? 1 : 0);
    }
    if (st) {
        ok = flowd_collect_rows(st, arr, flowd_smart_qos_category_row_json, "smart qos categories");
        if (!ok)
            error = "smart_qos_categories_unavailable";
        sqlite3_finalize(st);
    } else {
        ok = 0;
        error = "smart_qos_categories_unavailable";
    }
    flowd_list_total_add(resp, &ok, &error, "SELECT COUNT(*) FROM flowd_smart_qos_categories",
                         "smart_qos_categories_count_unavailable");
    json_object_object_add(resp, "ok", json_object_new_boolean(ok));
    json_object_object_add(resp, "categories", arr);
    if (error[0])
        json_object_object_add(resp, "error", json_object_new_string(error));
    return resp;
}

static int flowd_smart_qos_category_load_existing(const char *id,
                                                  char *name, size_t name_len,
                                                  int *enabled,
                                                  char *category, size_t category_len,
                                                  int *priority,
                                                  char *qos_class, size_t qos_class_len,
                                                  int *latency_target_ms,
                                                  char *remark, size_t remark_len)
{
    sqlite3_stmt *st;
    int rc;

    if (!flowd_id_ok(id))
        return -1;
    st = flowd_config_prepare(
        "SELECT name,enabled,category,priority,qos_class,latency_target_ms,remark "
        "FROM flowd_smart_qos_categories WHERE id=?1");
    if (!st)
        return -1;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) {
        snprintf(name, name_len, "%s",
                 sqlite3_column_text(st, 0) ? (const char *)sqlite3_column_text(st, 0) : "");
        if (enabled)
            *enabled = sqlite3_column_int(st, 1) ? 1 : 0;
        snprintf(category, category_len, "%s",
                 sqlite3_column_text(st, 2) ? (const char *)sqlite3_column_text(st, 2) : "");
        if (priority)
            *priority = sqlite3_column_int(st, 3);
        snprintf(qos_class, qos_class_len, "%s",
                 sqlite3_column_text(st, 4) ? (const char *)sqlite3_column_text(st, 4) : "");
        if (latency_target_ms)
            *latency_target_ms = sqlite3_column_int(st, 5);
        snprintf(remark, remark_len, "%s",
                 sqlite3_column_text(st, 6) ? (const char *)sqlite3_column_text(st, 6) : "");
        sqlite3_finalize(st);
        return 1;
    }
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

static int flowd_smart_qos_category_save_one(struct json_object *body)
{
    sqlite3_stmt *st;
    char generated_id[FLOWD_MAX_ID];
    char name_buf[129] = "";
    char category_buf[65] = "";
    char qos_class_buf[FLOWD_MAX_ID] = "";
    char remark_buf[257] = "";
    const char *id, *name, *category, *qos_class, *remark;
    int enabled, priority, latency_target_ms, ok = 0;
    int load_existing = 0;
    int64_t now = flowd_now_s();

    if (!body || !json_object_is_type(body, json_type_object))
        return -1;
    enabled = 1;
    priority = 500;
    latency_target_ms = 0;
    id = flowd_json_str(body, "id", "");
    category = flowd_json_str(body, "category", "");
    if (!id[0]) {
        if (flowd_smart_qos_id_for_category(category, generated_id, sizeof(generated_id))) {
            load_existing = 1;
        } else {
            flowd_make_id("smart-qos", generated_id, sizeof(generated_id));
        }
        id = generated_id;
    } else {
        load_existing = 1;
    }
    if (load_existing) {
        int existing;

        existing = flowd_smart_qos_category_load_existing(id, name_buf, sizeof(name_buf),
                                                          &enabled, category_buf, sizeof(category_buf),
                                                          &priority, qos_class_buf, sizeof(qos_class_buf),
                                                          &latency_target_ms,
                                                          remark_buf, sizeof(remark_buf));
        if (existing < 0)
            return -1;
    }
    name = flowd_json_str(body, "name", name_buf);
    enabled = flowd_json_bool(body, "enabled", enabled);
    category = flowd_json_str(body, "category", category_buf);
    priority = flowd_json_int(body, "priority", priority);
    qos_class = flowd_json_str(body, "qos_class", qos_class_buf);
    latency_target_ms = flowd_json_int(body, "latency_target_ms", latency_target_ms);
    remark = flowd_json_str(body, "remark", remark_buf);
    if (!flowd_id_ok(id) || !flowd_text_ok(name, 128) ||
        !flowd_token_ok(category, 64) || priority < 0 || priority > 1000000 ||
        !flowd_optional_id_ok(qos_class) || latency_target_ms < 0 ||
        latency_target_ms > 600000 || !flowd_text_ok(remark, 256))
        return -1;
    st = flowd_config_prepare(
        "INSERT INTO flowd_smart_qos_categories"
        "(id,name,enabled,category,priority,qos_class,latency_target_ms,remark,created_at,updated_at) "
        "VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?9) "
        "ON CONFLICT(id) DO UPDATE SET name=excluded.name,enabled=excluded.enabled,"
        "category=excluded.category,priority=excluded.priority,qos_class=excluded.qos_class,"
        "latency_target_ms=excluded.latency_target_ms,remark=excluded.remark,updated_at=excluded.updated_at");
    if (st) {
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, name, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 3, enabled ? 1 : 0);
        sqlite3_bind_text(st, 4, category, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 5, priority);
        sqlite3_bind_text(st, 6, qos_class, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 7, latency_target_ms);
        sqlite3_bind_text(st, 8, remark, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 9, now);
        ok = sqlite3_step(st) == SQLITE_DONE;
        sqlite3_finalize(st);
    }
    return ok ? 0 : -1;
}

struct json_object *flowd_smart_qos_category_update(struct json_object *body)
{
    struct json_object *arr = NULL;
    int ok = 1, saved = 0, i, n;
    struct json_object *resp;

    if (!body || !json_object_is_type(body, json_type_object))
        return flowd_error("invalid_request", "smart qos category body must be an object");
    if (json_object_object_get_ex(body, "categories", &arr) && arr &&
        json_object_is_type(arr, json_type_array)) {
        n = json_object_array_length(arr);
        for (i = 0; i < n; i++) {
            if (flowd_smart_qos_category_save_one(json_object_array_get_idx(arr, i)) == 0)
                saved++;
            else
                ok = 0;
        }
    } else {
        ok = flowd_smart_qos_category_save_one(body) == 0;
        saved = ok ? 1 : 0;
    }
    resp = flowd_smart_qos_categories_json(NULL);
    flowd_response_set_ok(resp, ok);
    json_object_object_add(resp, "saved", json_object_new_int(saved));
    if (!ok)
        json_object_object_add(resp, "error", json_object_new_string("partial_or_failed_save"));
    return resp;
}

struct json_object *flowd_smart_qos_category_delete(struct json_object *body)
{
    sqlite3_stmt *st;
    const char *id = flowd_json_str(body, "id", "");
    int ok = 0;
    struct json_object *resp;

    if (!flowd_id_ok(id))
        return flowd_error("invalid_id", "invalid smart qos category id");
    st = flowd_config_prepare("DELETE FROM flowd_smart_qos_categories WHERE id=?1");
    if (st) {
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        ok = sqlite3_step(st) == SQLITE_DONE && sqlite3_changes(g_flowd_config_db) > 0;
        sqlite3_finalize(st);
    }
    resp = flowd_smart_qos_categories_json(NULL);
    flowd_response_set_ok(resp, ok);
    json_object_object_add(resp, "deleted", json_object_new_boolean(ok));
    if (!ok)
        json_object_object_add(resp, "error", json_object_new_string("not_found"));
    return resp;
}

static int flowd_smart_qos_compile_json(struct json_object *out)
{
    sqlite3_stmt *st;
    struct json_object *categories = json_object_new_array();
    int enabled_count = 0;
    int missing_refs = 0;

    st = flowd_config_prepare(
        "SELECT id,name,enabled,category,priority,qos_class,latency_target_ms,remark,updated_at "
        "FROM flowd_smart_qos_categories WHERE enabled=1 ORDER BY priority,category");
    if (st) {
        while (sqlite3_step(st) == SQLITE_ROW) {
            const char *qos_class = (const char *)sqlite3_column_text(st, 5);
            struct json_object *o = json_object_new_object();
            struct json_object *missing = json_object_new_array();
            int local_missing = 0;

            if (qos_class && qos_class[0] && !flowd_id_exists_in("flowd_qos_classes", qos_class)) {
                flowd_split_rule_missing_ref(missing, "qos_class", qos_class);
                local_missing++;
            }
            json_object_object_add(o, "id", flowd_sqlite_text_json(st, 0));
            json_object_object_add(o, "name", flowd_sqlite_text_json(st, 1));
            json_object_object_add(o, "category", flowd_sqlite_text_json(st, 3));
            json_object_object_add(o, "priority", json_object_new_int(sqlite3_column_int(st, 4)));
            json_object_object_add(o, "qos_class", json_object_new_string(qos_class ? qos_class : ""));
            json_object_object_add(o, "latency_target_ms", json_object_new_int(sqlite3_column_int(st, 6)));
            json_object_object_add(o, "runtime_kind", json_object_new_string("smart_qos_category"));
            json_object_object_add(o, "state_store", json_object_new_string(FLOWD_DEFAULT_FLOW_DB_PATH));
            json_object_object_add(o, "state", json_object_new_string(local_missing ? "blocked" : "planned"));
            json_object_object_add(o, "missing_refs", missing);
            json_object_object_add(o, "mutates_dataplane", json_object_new_boolean(0));
            json_object_array_add(categories, o);
            missing_refs += local_missing;
            enabled_count++;
        }
        sqlite3_finalize(st);
    }
    json_object_object_add(out, "total", json_object_new_int(flowd_count_sql("SELECT COUNT(*) FROM flowd_smart_qos_categories")));
    json_object_object_add(out, "enabled", json_object_new_int(enabled_count));
    json_object_object_add(out, "missing_refs", json_object_new_int(missing_refs));
    json_object_object_add(out, "categories", categories);
    return missing_refs;
}

static int flowd_quota_scope_ok(const char *scope)
{
    return scope && (!strcmp(scope, "daily") || !strcmp(scope, "monthly") ||
                     !strcmp(scope, "rolling_24h") || !strcmp(scope, "session"));
}

static int flowd_quota_action_ok(const char *action)
{
    return action && (!strcmp(action, "throttle") || !strcmp(action, "block") ||
                      !strcmp(action, "notify") || !strcmp(action, "mark"));
}

static int64_t flowd_json_int64_local(struct json_object *o, const char *key, int64_t def)
{
    struct json_object *v = NULL;

    if (!o || !key || !json_object_object_get_ex(o, key, &v) || !v)
        return def;
    return json_object_get_int64(v);
}

static void flowd_quota_rule_row_json(struct json_object *arr, sqlite3_stmt *st)
{
    struct json_object *o = json_object_new_object();

    json_object_object_add(o, "id", flowd_sqlite_text_json(st, 0));
    json_object_object_add(o, "name", flowd_sqlite_text_json(st, 1));
    json_object_object_add(o, "enabled", json_object_new_boolean(sqlite3_column_int(st, 2)));
    json_object_object_add(o, "priority", json_object_new_int(sqlite3_column_int(st, 3)));
    json_object_object_add(o, "scope", flowd_sqlite_text_json(st, 4));
    json_object_object_add(o, "action", flowd_sqlite_text_json(st, 5));
    json_object_object_add(o, "target_object", flowd_sqlite_text_json(st, 6));
    json_object_object_add(o, "limit_bytes", json_object_new_int64(sqlite3_column_int64(st, 7)));
    json_object_object_add(o, "reset_hour", json_object_new_int(sqlite3_column_int(st, 8)));
    json_object_object_add(o, "timezone", flowd_sqlite_text_json(st, 9));
    json_object_object_add(o, "throttle_class", flowd_sqlite_text_json(st, 10));
    json_object_object_add(o, "notify", json_object_new_boolean(sqlite3_column_int(st, 11)));
    json_object_object_add(o, "log_event", json_object_new_boolean(sqlite3_column_int(st, 12)));
    json_object_object_add(o, "remark", flowd_sqlite_text_json(st, 13));
    json_object_object_add(o, "updated_at", json_object_new_int64(sqlite3_column_int64(st, 14)));
    json_object_array_add(arr, o);
}

struct json_object *flowd_quota_rules_json(struct json_object *body)
{
    sqlite3_stmt *st = NULL;
    struct json_object *resp = json_object_new_object();
    struct json_object *arr = json_object_new_array();
    const char *id = flowd_json_str(body, "id", "");
    int include_disabled = flowd_json_bool(body, "include_disabled", 1);
    int ok = 1;
    const char *error = "";

    if (id && id[0] && !flowd_id_ok(id))
        return flowd_error("invalid_id", "invalid quota rule id");
    if (id && id[0]) {
        st = flowd_config_prepare(
            "SELECT id,name,enabled,priority,scope,action,target_object,limit_bytes,reset_hour,timezone,"
            "throttle_class,notify,log_event,remark,updated_at FROM flowd_quota_rules WHERE id=?1");
        if (st)
            sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    } else {
        st = flowd_config_prepare(
            "SELECT id,name,enabled,priority,scope,action,target_object,limit_bytes,reset_hour,timezone,"
            "throttle_class,notify,log_event,remark,updated_at FROM flowd_quota_rules "
            "WHERE (?1 OR enabled=1) ORDER BY priority,id");
        if (st)
            sqlite3_bind_int(st, 1, include_disabled ? 1 : 0);
    }
    if (st) {
        ok = flowd_collect_rows(st, arr, flowd_quota_rule_row_json, "quota rules");
        if (!ok)
            error = "quota_rules_unavailable";
        sqlite3_finalize(st);
    } else {
        ok = 0;
        error = "quota_rules_unavailable";
    }
    flowd_list_total_add(resp, &ok, &error, "SELECT COUNT(*) FROM flowd_quota_rules",
                         "quota_rules_count_unavailable");
    json_object_object_add(resp, "ok", json_object_new_boolean(ok));
    json_object_object_add(resp, "rules", arr);
    if (error[0])
        json_object_object_add(resp, "error", json_object_new_string(error));
    return resp;
}

static int flowd_quota_rule_load_existing(const char *id,
                                          char *name, size_t name_len,
                                          int *enabled, int *priority,
                                          char *scope, size_t scope_len,
                                          char *action, size_t action_len,
                                          char *target_object, size_t target_object_len,
                                          int64_t *limit_bytes,
                                          int *reset_hour,
                                          char *timezone, size_t timezone_len,
                                          char *throttle_class, size_t throttle_class_len,
                                          int *notify, int *log_event,
                                          char *remark, size_t remark_len)
{
    sqlite3_stmt *st;
    int rc;

    if (!flowd_id_ok(id))
        return -1;
    st = flowd_config_prepare(
        "SELECT name,enabled,priority,scope,action,target_object,limit_bytes,reset_hour,timezone,"
        "throttle_class,notify,log_event,remark FROM flowd_quota_rules WHERE id=?1");
    if (!st)
        return -1;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) {
        snprintf(name, name_len, "%s",
                 sqlite3_column_text(st, 0) ? (const char *)sqlite3_column_text(st, 0) : "");
        if (enabled)
            *enabled = sqlite3_column_int(st, 1) ? 1 : 0;
        if (priority)
            *priority = sqlite3_column_int(st, 2);
        snprintf(scope, scope_len, "%s",
                 sqlite3_column_text(st, 3) ? (const char *)sqlite3_column_text(st, 3) : "daily");
        snprintf(action, action_len, "%s",
                 sqlite3_column_text(st, 4) ? (const char *)sqlite3_column_text(st, 4) : "throttle");
        snprintf(target_object, target_object_len, "%s",
                 sqlite3_column_text(st, 5) ? (const char *)sqlite3_column_text(st, 5) : "");
        if (limit_bytes)
            *limit_bytes = sqlite3_column_int64(st, 6);
        if (reset_hour)
            *reset_hour = sqlite3_column_int(st, 7);
        snprintf(timezone, timezone_len, "%s",
                 sqlite3_column_text(st, 8) ? (const char *)sqlite3_column_text(st, 8) : "local");
        snprintf(throttle_class, throttle_class_len, "%s",
                 sqlite3_column_text(st, 9) ? (const char *)sqlite3_column_text(st, 9) : "");
        if (notify)
            *notify = sqlite3_column_int(st, 10) ? 1 : 0;
        if (log_event)
            *log_event = sqlite3_column_int(st, 11) ? 1 : 0;
        snprintf(remark, remark_len, "%s",
                 sqlite3_column_text(st, 12) ? (const char *)sqlite3_column_text(st, 12) : "");
        sqlite3_finalize(st);
        return 1;
    }
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

static int flowd_quota_rule_save_one(struct json_object *body)
{
    sqlite3_stmt *st;
    char generated_id[FLOWD_MAX_ID];
    char name_buf[129] = "";
    char scope_buf[32] = "daily";
    char action_buf[32] = "throttle";
    char target_object_buf[FLOWD_MAX_ID] = "";
    char timezone_buf[65] = "local";
    char throttle_class_buf[FLOWD_MAX_ID] = "";
    char remark_buf[257] = "";
    const char *id, *name, *scope, *action, *target_object, *timezone, *throttle_class, *remark;
    int enabled, priority, reset_hour, notify, log_event, ok = 0;
    int64_t limit_bytes, now = flowd_now_s();

    if (!body || !json_object_is_type(body, json_type_object))
        return -1;
    enabled = 1;
    priority = 1000;
    reset_hour = 0;
    notify = 1;
    log_event = 1;
    limit_bytes = 0;
    id = flowd_json_str(body, "id", "");
    if (!id[0]) {
        flowd_make_id("quota-rule", generated_id, sizeof(generated_id));
        id = generated_id;
    } else {
        int existing;

        existing = flowd_quota_rule_load_existing(id, name_buf, sizeof(name_buf),
                                                  &enabled, &priority,
                                                  scope_buf, sizeof(scope_buf),
                                                  action_buf, sizeof(action_buf),
                                                  target_object_buf, sizeof(target_object_buf),
                                                  &limit_bytes, &reset_hour,
                                                  timezone_buf, sizeof(timezone_buf),
                                                  throttle_class_buf, sizeof(throttle_class_buf),
                                                  &notify, &log_event,
                                                  remark_buf, sizeof(remark_buf));
        if (existing < 0)
            return -1;
    }
    name = flowd_json_str(body, "name", name_buf);
    enabled = flowd_json_bool(body, "enabled", enabled);
    priority = flowd_json_int(body, "priority", priority);
    scope = flowd_json_str(body, "scope", scope_buf);
    action = flowd_json_str(body, "action", action_buf);
    target_object = flowd_json_str(body, "target_object", target_object_buf);
    limit_bytes = flowd_json_int64_local(body, "limit_bytes", limit_bytes);
    reset_hour = flowd_json_int(body, "reset_hour", reset_hour);
    timezone = flowd_json_str(body, "timezone", timezone_buf);
    throttle_class = flowd_json_str(body, "throttle_class", throttle_class_buf);
    notify = flowd_json_bool(body, "notify", notify);
    log_event = flowd_json_bool(body, "log_event", log_event);
    remark = flowd_json_str(body, "remark", remark_buf);
    if (!flowd_id_ok(id) || !flowd_text_ok(name, 128) || priority < 0 || priority > 1000000 ||
        !flowd_quota_scope_ok(scope) || !flowd_quota_action_ok(action) ||
        !flowd_id_ok(target_object) || limit_bytes <= 0 || limit_bytes > INT64_C(1000000000000000) ||
        reset_hour < 0 || reset_hour > 23 || !flowd_optional_token_ok(timezone, 64) ||
        !flowd_optional_id_ok(throttle_class) || !flowd_text_ok(remark, 256))
        return -1;
    if (!strcmp(action, "throttle") && !throttle_class[0])
        return -1;
    st = flowd_config_prepare(
        "INSERT INTO flowd_quota_rules"
        "(id,name,enabled,priority,scope,action,target_object,limit_bytes,reset_hour,timezone,"
        "throttle_class,notify,log_event,remark,created_at,updated_at) "
        "VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?15) "
        "ON CONFLICT(id) DO UPDATE SET name=excluded.name,enabled=excluded.enabled,"
        "priority=excluded.priority,scope=excluded.scope,action=excluded.action,"
        "target_object=excluded.target_object,limit_bytes=excluded.limit_bytes,"
        "reset_hour=excluded.reset_hour,timezone=excluded.timezone,throttle_class=excluded.throttle_class,"
        "notify=excluded.notify,log_event=excluded.log_event,remark=excluded.remark,"
        "updated_at=excluded.updated_at");
    if (st) {
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, name, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 3, enabled ? 1 : 0);
        sqlite3_bind_int(st, 4, priority);
        sqlite3_bind_text(st, 5, scope, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 6, action, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 7, target_object, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 8, limit_bytes);
        sqlite3_bind_int(st, 9, reset_hour);
        sqlite3_bind_text(st, 10, timezone, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 11, throttle_class, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 12, notify ? 1 : 0);
        sqlite3_bind_int(st, 13, log_event ? 1 : 0);
        sqlite3_bind_text(st, 14, remark, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 15, now);
        ok = sqlite3_step(st) == SQLITE_DONE;
        sqlite3_finalize(st);
    }
    return ok ? 0 : -1;
}

struct json_object *flowd_quota_rule_update(struct json_object *body)
{
    struct json_object *arr = NULL;
    int ok = 1, saved = 0, i, n;
    struct json_object *resp;

    if (!body || !json_object_is_type(body, json_type_object))
        return flowd_error("invalid_request", "quota rule body must be an object");
    if (json_object_object_get_ex(body, "rules", &arr) && arr &&
        json_object_is_type(arr, json_type_array)) {
        n = json_object_array_length(arr);
        for (i = 0; i < n; i++) {
            if (flowd_quota_rule_save_one(json_object_array_get_idx(arr, i)) == 0)
                saved++;
            else
                ok = 0;
        }
    } else {
        ok = flowd_quota_rule_save_one(body) == 0;
        saved = ok ? 1 : 0;
    }
    resp = flowd_quota_rules_json(NULL);
    flowd_response_set_ok(resp, ok);
    json_object_object_add(resp, "saved", json_object_new_int(saved));
    if (!ok)
        json_object_object_add(resp, "error", json_object_new_string("partial_or_failed_save"));
    return resp;
}

struct json_object *flowd_quota_rule_delete(struct json_object *body)
{
    sqlite3_stmt *st;
    const char *id = flowd_json_str(body, "id", "");
    int ok = 0;
    struct json_object *resp;

    if (!flowd_id_ok(id))
        return flowd_error("invalid_id", "invalid quota rule id");
    st = flowd_config_prepare("DELETE FROM flowd_quota_rules WHERE id=?1");
    if (st) {
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        ok = sqlite3_step(st) == SQLITE_DONE && sqlite3_changes(g_flowd_config_db) > 0;
        sqlite3_finalize(st);
    }
    resp = flowd_quota_rules_json(NULL);
    flowd_response_set_ok(resp, ok);
    json_object_object_add(resp, "deleted", json_object_new_boolean(ok));
    if (!ok)
        json_object_object_add(resp, "error", json_object_new_string("not_found"));
    return resp;
}

static int flowd_quota_rules_compile_json(struct json_object *out)
{
    sqlite3_stmt *st;
    struct json_object *rules = json_object_new_array();
    int enabled_count = 0;
    int missing_refs = 0;

    st = flowd_config_prepare(
        "SELECT id,name,enabled,priority,scope,action,target_object,limit_bytes,reset_hour,timezone,"
        "throttle_class,notify,log_event,remark,updated_at FROM flowd_quota_rules "
        "WHERE enabled=1 ORDER BY priority,id");
    if (st) {
        while (sqlite3_step(st) == SQLITE_ROW) {
            const char *action = (const char *)sqlite3_column_text(st, 5);
            const char *target_object = (const char *)sqlite3_column_text(st, 6);
            const char *throttle_class = (const char *)sqlite3_column_text(st, 10);
            struct json_object *o = json_object_new_object();
            struct json_object *missing = json_object_new_array();
            int local_missing = 0;

            if (!flowd_id_exists_in("flowd_objects", target_object)) {
                flowd_split_rule_missing_ref(missing, "target_object", target_object);
                local_missing++;
            }
            if (action && !strcmp(action, "throttle") &&
                (!throttle_class || !throttle_class[0] ||
                 !flowd_id_exists_in("flowd_qos_classes", throttle_class))) {
                flowd_split_rule_missing_ref(missing, "throttle_class", throttle_class);
                local_missing++;
            }
            json_object_object_add(o, "id", flowd_sqlite_text_json(st, 0));
            json_object_object_add(o, "name", flowd_sqlite_text_json(st, 1));
            json_object_object_add(o, "priority", json_object_new_int(sqlite3_column_int(st, 3)));
            json_object_object_add(o, "scope", flowd_sqlite_text_json(st, 4));
            json_object_object_add(o, "action", json_object_new_string(action ? action : ""));
            json_object_object_add(o, "target_object", json_object_new_string(target_object ? target_object : ""));
            json_object_object_add(o, "limit_bytes", json_object_new_int64(sqlite3_column_int64(st, 7)));
            json_object_object_add(o, "reset_hour", json_object_new_int(sqlite3_column_int(st, 8)));
            json_object_object_add(o, "timezone", flowd_sqlite_text_json(st, 9));
            json_object_object_add(o, "throttle_class", json_object_new_string(throttle_class ? throttle_class : ""));
            json_object_object_add(o, "notify", json_object_new_boolean(sqlite3_column_int(st, 11)));
            json_object_object_add(o, "log_event", json_object_new_boolean(sqlite3_column_int(st, 12)));
            json_object_object_add(o, "runtime_kind", json_object_new_string("quota_rule"));
            json_object_object_add(o, "state_store", json_object_new_string(FLOWD_DEFAULT_FLOW_DB_PATH));
            json_object_object_add(o, "state", json_object_new_string(local_missing ? "blocked" : "planned"));
            json_object_object_add(o, "missing_refs", missing);
            json_object_object_add(o, "mutates_dataplane", json_object_new_boolean(0));
            json_object_array_add(rules, o);
            missing_refs += local_missing;
            enabled_count++;
        }
        sqlite3_finalize(st);
    }
    json_object_object_add(out, "total", json_object_new_int(flowd_count_sql("SELECT COUNT(*) FROM flowd_quota_rules")));
    json_object_object_add(out, "enabled", json_object_new_int(enabled_count));
    json_object_object_add(out, "missing_refs", json_object_new_int(missing_refs));
    json_object_object_add(out, "rules", rules);
    return missing_refs;
}

static int flowd_conn_limit_scope_ok(const char *scope)
{
    return scope && (!strcmp(scope, "per_host") || !strcmp(scope, "per_src") ||
                     !strcmp(scope, "per_dst") || !strcmp(scope, "global"));
}

static int flowd_conn_limit_action_ok(const char *action)
{
    return action && (!strcmp(action, "reject_new") || !strcmp(action, "drop_new") ||
                      !strcmp(action, "mark") || !strcmp(action, "log_only"));
}

static void flowd_conn_limit_rule_row_json(struct json_object *arr, sqlite3_stmt *st)
{
    struct json_object *o = json_object_new_object();

    json_object_object_add(o, "id", flowd_sqlite_text_json(st, 0));
    json_object_object_add(o, "name", flowd_sqlite_text_json(st, 1));
    json_object_object_add(o, "enabled", json_object_new_boolean(sqlite3_column_int(st, 2)));
    json_object_object_add(o, "priority", json_object_new_int(sqlite3_column_int(st, 3)));
    json_object_object_add(o, "scope", flowd_sqlite_text_json(st, 4));
    json_object_object_add(o, "action", flowd_sqlite_text_json(st, 5));
    json_object_object_add(o, "src_object", flowd_sqlite_text_json(st, 6));
    json_object_object_add(o, "dst_object", flowd_sqlite_text_json(st, 7));
    json_object_object_add(o, "service_object", flowd_sqlite_text_json(st, 8));
    json_object_object_add(o, "time_object", flowd_sqlite_text_json(st, 9));
    json_object_object_add(o, "proto", flowd_sqlite_text_json(st, 10));
    json_object_object_add(o, "conn_limit", json_object_new_int(sqlite3_column_int(st, 11)));
    json_object_object_add(o, "burst", json_object_new_int(sqlite3_column_int(st, 12)));
    json_object_object_add(o, "log_event", json_object_new_boolean(sqlite3_column_int(st, 13)));
    json_object_object_add(o, "remark", flowd_sqlite_text_json(st, 14));
    json_object_object_add(o, "updated_at", json_object_new_int64(sqlite3_column_int64(st, 15)));
    json_object_array_add(arr, o);
}

struct json_object *flowd_conn_limit_rules_json(struct json_object *body)
{
    sqlite3_stmt *st = NULL;
    struct json_object *resp = json_object_new_object();
    struct json_object *arr = json_object_new_array();
    const char *id = flowd_json_str(body, "id", "");
    int include_disabled = flowd_json_bool(body, "include_disabled", 1);
    int ok = 1;
    const char *error = "";

    if (id && id[0] && !flowd_id_ok(id))
        return flowd_error("invalid_id", "invalid connection-limit rule id");
    if (id && id[0]) {
        st = flowd_config_prepare(
            "SELECT id,name,enabled,priority,scope,action,src_object,dst_object,service_object,time_object,"
            "proto,conn_limit,burst,log_event,remark,updated_at FROM flowd_conn_limit_rules WHERE id=?1");
        if (st)
            sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    } else {
        st = flowd_config_prepare(
            "SELECT id,name,enabled,priority,scope,action,src_object,dst_object,service_object,time_object,"
            "proto,conn_limit,burst,log_event,remark,updated_at FROM flowd_conn_limit_rules "
            "WHERE (?1 OR enabled=1) ORDER BY priority,id");
        if (st)
            sqlite3_bind_int(st, 1, include_disabled ? 1 : 0);
    }
    if (st) {
        ok = flowd_collect_rows(st, arr, flowd_conn_limit_rule_row_json, "connection limit rules");
        if (!ok)
            error = "conn_limit_rules_unavailable";
        sqlite3_finalize(st);
    } else {
        ok = 0;
        error = "conn_limit_rules_unavailable";
    }
    flowd_list_total_add(resp, &ok, &error, "SELECT COUNT(*) FROM flowd_conn_limit_rules",
                         "conn_limit_rules_count_unavailable");
    json_object_object_add(resp, "ok", json_object_new_boolean(ok));
    json_object_object_add(resp, "rules", arr);
    if (error[0])
        json_object_object_add(resp, "error", json_object_new_string(error));
    return resp;
}

static int flowd_conn_limit_rule_load_existing(const char *id,
                                               char *name, size_t name_len,
                                               int *enabled, int *priority,
                                               char *scope, size_t scope_len,
                                               char *action, size_t action_len,
                                               char *src_object, size_t src_object_len,
                                               char *dst_object, size_t dst_object_len,
                                               char *service_object, size_t service_object_len,
                                               char *time_object, size_t time_object_len,
                                               char *proto, size_t proto_len,
                                               int *conn_limit, int *burst,
                                               int *log_event,
                                               char *remark, size_t remark_len)
{
    sqlite3_stmt *st;
    int rc;

    if (!flowd_id_ok(id))
        return -1;
    st = flowd_config_prepare(
        "SELECT name,enabled,priority,scope,action,src_object,dst_object,service_object,time_object,"
        "proto,conn_limit,burst,log_event,remark FROM flowd_conn_limit_rules WHERE id=?1");
    if (!st)
        return -1;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) {
        snprintf(name, name_len, "%s",
                 sqlite3_column_text(st, 0) ? (const char *)sqlite3_column_text(st, 0) : "");
        if (enabled)
            *enabled = sqlite3_column_int(st, 1) ? 1 : 0;
        if (priority)
            *priority = sqlite3_column_int(st, 2);
        snprintf(scope, scope_len, "%s",
                 sqlite3_column_text(st, 3) ? (const char *)sqlite3_column_text(st, 3) : "per_host");
        snprintf(action, action_len, "%s",
                 sqlite3_column_text(st, 4) ? (const char *)sqlite3_column_text(st, 4) : "reject_new");
        snprintf(src_object, src_object_len, "%s",
                 sqlite3_column_text(st, 5) ? (const char *)sqlite3_column_text(st, 5) : "");
        snprintf(dst_object, dst_object_len, "%s",
                 sqlite3_column_text(st, 6) ? (const char *)sqlite3_column_text(st, 6) : "");
        snprintf(service_object, service_object_len, "%s",
                 sqlite3_column_text(st, 7) ? (const char *)sqlite3_column_text(st, 7) : "");
        snprintf(time_object, time_object_len, "%s",
                 sqlite3_column_text(st, 8) ? (const char *)sqlite3_column_text(st, 8) : "");
        snprintf(proto, proto_len, "%s",
                 sqlite3_column_text(st, 9) ? (const char *)sqlite3_column_text(st, 9) : "any");
        if (conn_limit)
            *conn_limit = sqlite3_column_int(st, 10);
        if (burst)
            *burst = sqlite3_column_int(st, 11);
        if (log_event)
            *log_event = sqlite3_column_int(st, 12) ? 1 : 0;
        snprintf(remark, remark_len, "%s",
                 sqlite3_column_text(st, 13) ? (const char *)sqlite3_column_text(st, 13) : "");
        sqlite3_finalize(st);
        return 1;
    }
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

static int flowd_conn_limit_rule_save_one(struct json_object *body)
{
    sqlite3_stmt *st;
    char generated_id[FLOWD_MAX_ID];
    char name_buf[129] = "";
    char scope_buf[32] = "per_host";
    char action_buf[32] = "reject_new";
    char src_object_buf[FLOWD_MAX_ID] = "";
    char dst_object_buf[FLOWD_MAX_ID] = "";
    char service_object_buf[FLOWD_MAX_ID] = "";
    char time_object_buf[FLOWD_MAX_ID] = "";
    char proto_buf[32] = "any";
    char remark_buf[257] = "";
    const char *id, *name, *scope, *action, *src_object, *dst_object;
    const char *service_object, *time_object, *proto, *remark;
    int enabled, priority, conn_limit, burst, log_event, ok = 0;
    int64_t now = flowd_now_s();

    if (!body || !json_object_is_type(body, json_type_object))
        return -1;
    enabled = 1;
    priority = 1000;
    conn_limit = 0;
    burst = 0;
    log_event = 1;
    id = flowd_json_str(body, "id", "");
    if (!id[0]) {
        flowd_make_id("conn-limit", generated_id, sizeof(generated_id));
        id = generated_id;
    } else {
        int existing;

        existing = flowd_conn_limit_rule_load_existing(id, name_buf, sizeof(name_buf),
                                                       &enabled, &priority,
                                                       scope_buf, sizeof(scope_buf),
                                                       action_buf, sizeof(action_buf),
                                                       src_object_buf, sizeof(src_object_buf),
                                                       dst_object_buf, sizeof(dst_object_buf),
                                                       service_object_buf, sizeof(service_object_buf),
                                                       time_object_buf, sizeof(time_object_buf),
                                                       proto_buf, sizeof(proto_buf),
                                                       &conn_limit, &burst, &log_event,
                                                       remark_buf, sizeof(remark_buf));
        if (existing < 0)
            return -1;
    }
    name = flowd_json_str(body, "name", name_buf);
    enabled = flowd_json_bool(body, "enabled", enabled);
    priority = flowd_json_int(body, "priority", priority);
    scope = flowd_json_str(body, "scope", scope_buf);
    action = flowd_json_str(body, "action", action_buf);
    src_object = flowd_json_str(body, "src_object", src_object_buf);
    dst_object = flowd_json_str(body, "dst_object", dst_object_buf);
    service_object = flowd_json_str(body, "service_object", service_object_buf);
    time_object = flowd_json_str(body, "time_object", time_object_buf);
    proto = flowd_json_str(body, "proto", proto_buf);
    conn_limit = flowd_json_int(body, "conn_limit", conn_limit);
    burst = flowd_json_int(body, "burst", burst);
    log_event = flowd_json_bool(body, "log_event", log_event);
    remark = flowd_json_str(body, "remark", remark_buf);
    if (!flowd_id_ok(id) || !flowd_text_ok(name, 128) || priority < 0 || priority > 1000000 ||
        !flowd_conn_limit_scope_ok(scope) || !flowd_conn_limit_action_ok(action) ||
        !flowd_optional_id_ok(src_object) || !flowd_optional_id_ok(dst_object) ||
        !flowd_optional_id_ok(service_object) || !flowd_optional_id_ok(time_object) ||
        !flowd_split_proto_ok(proto) || conn_limit <= 0 || conn_limit > 1000000 ||
        burst < 0 || burst > 1000000 || !flowd_text_ok(remark, 256))
        return -1;
    if (!src_object[0] && !dst_object[0] && strcmp(scope, "global"))
        return -1;
    st = flowd_config_prepare(
        "INSERT INTO flowd_conn_limit_rules"
        "(id,name,enabled,priority,scope,action,src_object,dst_object,service_object,time_object,"
        "proto,conn_limit,burst,log_event,remark,created_at,updated_at) "
        "VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?16) "
        "ON CONFLICT(id) DO UPDATE SET name=excluded.name,enabled=excluded.enabled,"
        "priority=excluded.priority,scope=excluded.scope,action=excluded.action,"
        "src_object=excluded.src_object,dst_object=excluded.dst_object,"
        "service_object=excluded.service_object,time_object=excluded.time_object,proto=excluded.proto,"
        "conn_limit=excluded.conn_limit,burst=excluded.burst,log_event=excluded.log_event,"
        "remark=excluded.remark,updated_at=excluded.updated_at");
    if (st) {
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, name, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 3, enabled ? 1 : 0);
        sqlite3_bind_int(st, 4, priority);
        sqlite3_bind_text(st, 5, scope, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 6, action, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 7, src_object, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 8, dst_object, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 9, service_object, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 10, time_object, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 11, proto, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 12, conn_limit);
        sqlite3_bind_int(st, 13, burst);
        sqlite3_bind_int(st, 14, log_event ? 1 : 0);
        sqlite3_bind_text(st, 15, remark, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 16, now);
        ok = sqlite3_step(st) == SQLITE_DONE;
        sqlite3_finalize(st);
    }
    return ok ? 0 : -1;
}

struct json_object *flowd_conn_limit_rule_update(struct json_object *body)
{
    struct json_object *arr = NULL;
    int ok = 1, saved = 0, i, n;
    struct json_object *resp;

    if (!body || !json_object_is_type(body, json_type_object))
        return flowd_error("invalid_request", "connection-limit rule body must be an object");
    if (json_object_object_get_ex(body, "rules", &arr) && arr &&
        json_object_is_type(arr, json_type_array)) {
        n = json_object_array_length(arr);
        for (i = 0; i < n; i++) {
            if (flowd_conn_limit_rule_save_one(json_object_array_get_idx(arr, i)) == 0)
                saved++;
            else
                ok = 0;
        }
    } else {
        ok = flowd_conn_limit_rule_save_one(body) == 0;
        saved = ok ? 1 : 0;
    }
    resp = flowd_conn_limit_rules_json(NULL);
    flowd_response_set_ok(resp, ok);
    json_object_object_add(resp, "saved", json_object_new_int(saved));
    if (!ok)
        json_object_object_add(resp, "error", json_object_new_string("partial_or_failed_save"));
    return resp;
}

struct json_object *flowd_conn_limit_rule_delete(struct json_object *body)
{
    sqlite3_stmt *st;
    const char *id = flowd_json_str(body, "id", "");
    int ok = 0;
    struct json_object *resp;

    if (!flowd_id_ok(id))
        return flowd_error("invalid_id", "invalid connection-limit rule id");
    st = flowd_config_prepare("DELETE FROM flowd_conn_limit_rules WHERE id=?1");
    if (st) {
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        ok = sqlite3_step(st) == SQLITE_DONE && sqlite3_changes(g_flowd_config_db) > 0;
        sqlite3_finalize(st);
    }
    resp = flowd_conn_limit_rules_json(NULL);
    flowd_response_set_ok(resp, ok);
    json_object_object_add(resp, "deleted", json_object_new_boolean(ok));
    if (!ok)
        json_object_object_add(resp, "error", json_object_new_string("not_found"));
    return resp;
}

static int flowd_conn_limit_rules_compile_json(struct json_object *out)
{
    sqlite3_stmt *st;
    struct json_object *rules = json_object_new_array();
    int enabled_count = 0;
    int missing_refs = 0;

    st = flowd_config_prepare(
        "SELECT id,name,enabled,priority,scope,action,src_object,dst_object,service_object,time_object,"
        "proto,conn_limit,burst,log_event,remark,updated_at FROM flowd_conn_limit_rules "
        "WHERE enabled=1 ORDER BY priority,id");
    if (st) {
        while (sqlite3_step(st) == SQLITE_ROW) {
            const char *src_object = (const char *)sqlite3_column_text(st, 6);
            const char *dst_object = (const char *)sqlite3_column_text(st, 7);
            const char *service_object = (const char *)sqlite3_column_text(st, 8);
            const char *time_object = (const char *)sqlite3_column_text(st, 9);
            struct json_object *o = json_object_new_object();
            struct json_object *missing = json_object_new_array();
            int local_missing = 0;

            if (!flowd_id_exists_in("flowd_objects", src_object)) {
                flowd_split_rule_missing_ref(missing, "src_object", src_object);
                local_missing++;
            }
            if (!flowd_id_exists_in("flowd_objects", dst_object)) {
                flowd_split_rule_missing_ref(missing, "dst_object", dst_object);
                local_missing++;
            }
            if (!flowd_id_exists_in("flowd_objects", service_object)) {
                flowd_split_rule_missing_ref(missing, "service_object", service_object);
                local_missing++;
            }
            if (!flowd_id_exists_in("flowd_objects", time_object)) {
                flowd_split_rule_missing_ref(missing, "time_object", time_object);
                local_missing++;
            }
            json_object_object_add(o, "id", flowd_sqlite_text_json(st, 0));
            json_object_object_add(o, "name", flowd_sqlite_text_json(st, 1));
            json_object_object_add(o, "priority", json_object_new_int(sqlite3_column_int(st, 3)));
            json_object_object_add(o, "scope", flowd_sqlite_text_json(st, 4));
            json_object_object_add(o, "action", flowd_sqlite_text_json(st, 5));
            json_object_object_add(o, "src_object", json_object_new_string(src_object ? src_object : ""));
            json_object_object_add(o, "dst_object", json_object_new_string(dst_object ? dst_object : ""));
            json_object_object_add(o, "service_object", json_object_new_string(service_object ? service_object : ""));
            json_object_object_add(o, "time_object", json_object_new_string(time_object ? time_object : ""));
            json_object_object_add(o, "proto", flowd_sqlite_text_json(st, 10));
            json_object_object_add(o, "conn_limit", json_object_new_int(sqlite3_column_int(st, 11)));
            json_object_object_add(o, "burst", json_object_new_int(sqlite3_column_int(st, 12)));
            json_object_object_add(o, "log_event", json_object_new_boolean(sqlite3_column_int(st, 13)));
            json_object_object_add(o, "runtime_kind", json_object_new_string("conn_limit_rule"));
            json_object_object_add(o, "state_store", json_object_new_string(FLOWD_DEFAULT_FLOW_DB_PATH));
            json_object_object_add(o, "state", json_object_new_string(local_missing ? "blocked" : "planned"));
            json_object_object_add(o, "missing_refs", missing);
            json_object_object_add(o, "mutates_dataplane", json_object_new_boolean(0));
            json_object_array_add(rules, o);
            missing_refs += local_missing;
            enabled_count++;
        }
        sqlite3_finalize(st);
    }
    json_object_object_add(out, "total", json_object_new_int(flowd_count_sql("SELECT COUNT(*) FROM flowd_conn_limit_rules")));
    json_object_object_add(out, "enabled", json_object_new_int(enabled_count));
    json_object_object_add(out, "missing_refs", json_object_new_int(missing_refs));
    json_object_object_add(out, "rules", rules);
    return missing_refs;
}

static int flowd_app_action_ok(const char *action)
{
    return action && (!strcmp(action, "accept") || !strcmp(action, "drop") ||
                      !strcmp(action, "route") || !strcmp(action, "qos") ||
                      !strcmp(action, "mark"));
}

static void flowd_app_rule_row_json(struct json_object *arr, sqlite3_stmt *st)
{
    struct json_object *o = json_object_new_object();

    json_object_object_add(o, "id", flowd_sqlite_text_json(st, 0));
    json_object_object_add(o, "name", flowd_sqlite_text_json(st, 1));
    json_object_object_add(o, "enabled", json_object_new_boolean(sqlite3_column_int(st, 2)));
    json_object_object_add(o, "priority", json_object_new_int(sqlite3_column_int(st, 3)));
    json_object_object_add(o, "action", flowd_sqlite_text_json(st, 4));
    json_object_object_add(o, "src_object", flowd_sqlite_text_json(st, 5));
    json_object_object_add(o, "app_object", flowd_sqlite_text_json(st, 6));
    json_object_object_add(o, "time_object", flowd_sqlite_text_json(st, 7));
    json_object_object_add(o, "route_group", flowd_sqlite_text_json(st, 8));
    json_object_object_add(o, "qos_class", flowd_sqlite_text_json(st, 9));
    json_object_object_add(o, "mark", flowd_sqlite_text_json(st, 10));
    json_object_object_add(o, "log_event", json_object_new_boolean(sqlite3_column_int(st, 11)));
    json_object_object_add(o, "remark", flowd_sqlite_text_json(st, 12));
    json_object_object_add(o, "updated_at", json_object_new_int64(sqlite3_column_int64(st, 13)));
    json_object_array_add(arr, o);
}

struct json_object *flowd_app_rules_json(struct json_object *body)
{
    sqlite3_stmt *st = NULL;
    struct json_object *resp = json_object_new_object();
    struct json_object *arr = json_object_new_array();
    const char *id = flowd_json_str(body, "id", "");
    int include_disabled = flowd_json_bool(body, "include_disabled", 1);
    int ok = 1;
    const char *error = "";

    if (id && id[0] && !flowd_id_ok(id))
        return flowd_error("invalid_id", "invalid app rule id");
    if (id && id[0]) {
        st = flowd_config_prepare(
            "SELECT id,name,enabled,priority,action,src_object,app_object,time_object,route_group,"
            "qos_class,mark,log_event,remark,updated_at FROM flowd_app_rules WHERE id=?1");
        if (st)
            sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    } else {
        st = flowd_config_prepare(
            "SELECT id,name,enabled,priority,action,src_object,app_object,time_object,route_group,"
            "qos_class,mark,log_event,remark,updated_at FROM flowd_app_rules "
            "WHERE (?1 OR enabled=1) ORDER BY priority,id");
        if (st)
            sqlite3_bind_int(st, 1, include_disabled ? 1 : 0);
    }
    if (st) {
        ok = flowd_collect_rows(st, arr, flowd_app_rule_row_json, "app rules");
        if (!ok)
            error = "app_rules_unavailable";
        sqlite3_finalize(st);
    } else {
        ok = 0;
        error = "app_rules_unavailable";
    }
    flowd_list_total_add(resp, &ok, &error, "SELECT COUNT(*) FROM flowd_app_rules",
                         "app_rules_count_unavailable");
    json_object_object_add(resp, "ok", json_object_new_boolean(ok));
    json_object_object_add(resp, "rules", arr);
    if (error[0])
        json_object_object_add(resp, "error", json_object_new_string(error));
    return resp;
}

static int flowd_app_rule_load_existing(const char *id,
                                        char *name, size_t name_len,
                                        int *enabled, int *priority,
                                        char *action, size_t action_len,
                                        char *src_object, size_t src_object_len,
                                        char *app_object, size_t app_object_len,
                                        char *time_object, size_t time_object_len,
                                        char *route_group, size_t route_group_len,
                                        char *qos_class, size_t qos_class_len,
                                        char *mark, size_t mark_len,
                                        int *log_event,
                                        char *remark, size_t remark_len)
{
    sqlite3_stmt *st;
    int rc;

    if (!flowd_id_ok(id))
        return -1;
    st = flowd_config_prepare(
        "SELECT name,enabled,priority,action,src_object,app_object,time_object,route_group,"
        "qos_class,mark,log_event,remark FROM flowd_app_rules WHERE id=?1");
    if (!st)
        return -1;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) {
        snprintf(name, name_len, "%s",
                 sqlite3_column_text(st, 0) ? (const char *)sqlite3_column_text(st, 0) : "");
        if (enabled)
            *enabled = sqlite3_column_int(st, 1) ? 1 : 0;
        if (priority)
            *priority = sqlite3_column_int(st, 2);
        snprintf(action, action_len, "%s",
                 sqlite3_column_text(st, 3) ? (const char *)sqlite3_column_text(st, 3) : "mark");
        snprintf(src_object, src_object_len, "%s",
                 sqlite3_column_text(st, 4) ? (const char *)sqlite3_column_text(st, 4) : "");
        snprintf(app_object, app_object_len, "%s",
                 sqlite3_column_text(st, 5) ? (const char *)sqlite3_column_text(st, 5) : "");
        snprintf(time_object, time_object_len, "%s",
                 sqlite3_column_text(st, 6) ? (const char *)sqlite3_column_text(st, 6) : "");
        snprintf(route_group, route_group_len, "%s",
                 sqlite3_column_text(st, 7) ? (const char *)sqlite3_column_text(st, 7) : "");
        snprintf(qos_class, qos_class_len, "%s",
                 sqlite3_column_text(st, 8) ? (const char *)sqlite3_column_text(st, 8) : "");
        snprintf(mark, mark_len, "%s",
                 sqlite3_column_text(st, 9) ? (const char *)sqlite3_column_text(st, 9) : "");
        if (log_event)
            *log_event = sqlite3_column_int(st, 10) ? 1 : 0;
        snprintf(remark, remark_len, "%s",
                 sqlite3_column_text(st, 11) ? (const char *)sqlite3_column_text(st, 11) : "");
        sqlite3_finalize(st);
        return 1;
    }
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

static int flowd_app_rule_save_one(struct json_object *body)
{
    sqlite3_stmt *st;
    char generated_id[FLOWD_MAX_ID];
    char name_buf[129] = "";
    char action_buf[32] = "mark";
    char src_object_buf[FLOWD_MAX_ID] = "";
    char app_object_buf[FLOWD_MAX_ID] = "";
    char time_object_buf[FLOWD_MAX_ID] = "";
    char route_group_buf[FLOWD_MAX_ID] = "";
    char qos_class_buf[FLOWD_MAX_ID] = "";
    char mark_buf[65] = "";
    char remark_buf[257] = "";
    const char *id, *name, *action, *src_object, *app_object, *time_object;
    const char *route_group, *qos_class, *mark, *remark;
    int enabled, priority, log_event, ok = 0;
    int64_t now = flowd_now_s();

    if (!body || !json_object_is_type(body, json_type_object))
        return -1;
    enabled = 1;
    priority = 1000;
    log_event = 1;
    id = flowd_json_str(body, "id", "");
    if (!id[0]) {
        flowd_make_id("app-rule", generated_id, sizeof(generated_id));
        id = generated_id;
    } else {
        int existing;

        existing = flowd_app_rule_load_existing(id, name_buf, sizeof(name_buf),
                                                &enabled, &priority,
                                                action_buf, sizeof(action_buf),
                                                src_object_buf, sizeof(src_object_buf),
                                                app_object_buf, sizeof(app_object_buf),
                                                time_object_buf, sizeof(time_object_buf),
                                                route_group_buf, sizeof(route_group_buf),
                                                qos_class_buf, sizeof(qos_class_buf),
                                                mark_buf, sizeof(mark_buf),
                                                &log_event,
                                                remark_buf, sizeof(remark_buf));
        if (existing < 0)
            return -1;
    }
    name = flowd_json_str(body, "name", name_buf);
    enabled = flowd_json_bool(body, "enabled", enabled);
    priority = flowd_json_int(body, "priority", priority);
    action = flowd_json_str(body, "action", action_buf);
    src_object = flowd_json_str(body, "src_object", src_object_buf);
    app_object = flowd_json_str(body, "app_object", app_object_buf);
    time_object = flowd_json_str(body, "time_object", time_object_buf);
    route_group = flowd_json_str(body, "route_group", route_group_buf);
    qos_class = flowd_json_str(body, "qos_class", qos_class_buf);
    mark = flowd_json_str(body, "mark", mark_buf);
    log_event = flowd_json_bool(body, "log_event", log_event);
    remark = flowd_json_str(body, "remark", remark_buf);
    if (!flowd_id_ok(id) || !flowd_text_ok(name, 128) || priority < 0 || priority > 1000000 ||
        !flowd_app_action_ok(action) || !flowd_optional_id_ok(src_object) ||
        !flowd_id_ok(app_object) || !flowd_optional_id_ok(time_object) ||
        !flowd_optional_id_ok(route_group) || !flowd_optional_id_ok(qos_class) ||
        !flowd_optional_token_ok(mark, 64) || !flowd_text_ok(remark, 256))
        return -1;
    if (!strcmp(action, "route") && !route_group[0])
        return -1;
    if (!strcmp(action, "qos") && !qos_class[0])
        return -1;
    st = flowd_config_prepare(
        "INSERT INTO flowd_app_rules"
        "(id,name,enabled,priority,action,src_object,app_object,time_object,route_group,qos_class,"
        "mark,log_event,remark,created_at,updated_at) "
        "VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?14) "
        "ON CONFLICT(id) DO UPDATE SET name=excluded.name,enabled=excluded.enabled,"
        "priority=excluded.priority,action=excluded.action,src_object=excluded.src_object,"
        "app_object=excluded.app_object,time_object=excluded.time_object,route_group=excluded.route_group,"
        "qos_class=excluded.qos_class,mark=excluded.mark,log_event=excluded.log_event,"
        "remark=excluded.remark,updated_at=excluded.updated_at");
    if (st) {
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, name, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 3, enabled ? 1 : 0);
        sqlite3_bind_int(st, 4, priority);
        sqlite3_bind_text(st, 5, action, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 6, src_object, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 7, app_object, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 8, time_object, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 9, route_group, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 10, qos_class, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 11, mark, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 12, log_event ? 1 : 0);
        sqlite3_bind_text(st, 13, remark, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 14, now);
        ok = sqlite3_step(st) == SQLITE_DONE;
        sqlite3_finalize(st);
    }
    return ok ? 0 : -1;
}

struct json_object *flowd_app_rule_update(struct json_object *body)
{
    struct json_object *arr = NULL;
    int ok = 1, saved = 0, i, n;
    struct json_object *resp;

    if (!body || !json_object_is_type(body, json_type_object))
        return flowd_error("invalid_request", "app rule body must be an object");
    if (json_object_object_get_ex(body, "rules", &arr) && arr &&
        json_object_is_type(arr, json_type_array)) {
        n = json_object_array_length(arr);
        for (i = 0; i < n; i++) {
            if (flowd_app_rule_save_one(json_object_array_get_idx(arr, i)) == 0)
                saved++;
            else
                ok = 0;
        }
    } else {
        ok = flowd_app_rule_save_one(body) == 0;
        saved = ok ? 1 : 0;
    }
    resp = flowd_app_rules_json(NULL);
    flowd_response_set_ok(resp, ok);
    json_object_object_add(resp, "saved", json_object_new_int(saved));
    if (!ok)
        json_object_object_add(resp, "error", json_object_new_string("partial_or_failed_save"));
    return resp;
}

struct json_object *flowd_app_rule_delete(struct json_object *body)
{
    sqlite3_stmt *st;
    const char *id = flowd_json_str(body, "id", "");
    int ok = 0;
    struct json_object *resp;

    if (!flowd_id_ok(id))
        return flowd_error("invalid_id", "invalid app rule id");
    st = flowd_config_prepare("DELETE FROM flowd_app_rules WHERE id=?1");
    if (st) {
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        ok = sqlite3_step(st) == SQLITE_DONE && sqlite3_changes(g_flowd_config_db) > 0;
        sqlite3_finalize(st);
    }
    resp = flowd_app_rules_json(NULL);
    flowd_response_set_ok(resp, ok);
    json_object_object_add(resp, "deleted", json_object_new_boolean(ok));
    if (!ok)
        json_object_object_add(resp, "error", json_object_new_string("not_found"));
    return resp;
}

static int flowd_app_rules_compile_json(struct json_object *out)
{
    sqlite3_stmt *st;
    struct json_object *rules = json_object_new_array();
    int enabled_count = 0;
    int missing_refs = 0;

    st = flowd_config_prepare(
        "SELECT id,name,enabled,priority,action,src_object,app_object,time_object,route_group,"
        "qos_class,mark,log_event,remark,updated_at FROM flowd_app_rules "
        "WHERE enabled=1 ORDER BY priority,id");
    if (st) {
        while (sqlite3_step(st) == SQLITE_ROW) {
            const char *action = (const char *)sqlite3_column_text(st, 4);
            const char *src_object = (const char *)sqlite3_column_text(st, 5);
            const char *app_object = (const char *)sqlite3_column_text(st, 6);
            const char *time_object = (const char *)sqlite3_column_text(st, 7);
            const char *route_group = (const char *)sqlite3_column_text(st, 8);
            const char *qos_class = (const char *)sqlite3_column_text(st, 9);
            struct json_object *o = json_object_new_object();
            struct json_object *missing = json_object_new_array();
            int local_missing = 0;

            if (!flowd_id_exists_in("flowd_objects", src_object)) {
                flowd_split_rule_missing_ref(missing, "src_object", src_object);
                local_missing++;
            }
            if (!flowd_id_exists_in("flowd_objects", app_object)) {
                flowd_split_rule_missing_ref(missing, "app_object", app_object);
                local_missing++;
            }
            if (!flowd_id_exists_in("flowd_objects", time_object)) {
                flowd_split_rule_missing_ref(missing, "time_object", time_object);
                local_missing++;
            }
            if (action && !strcmp(action, "route") &&
                (!route_group || !route_group[0] || !flowd_id_exists_in("flowd_route_groups", route_group))) {
                flowd_split_rule_missing_ref(missing, "route_group", route_group);
                local_missing++;
            }
            if (action && !strcmp(action, "qos") &&
                (!qos_class || !qos_class[0] || !flowd_id_exists_in("flowd_qos_classes", qos_class))) {
                flowd_split_rule_missing_ref(missing, "qos_class", qos_class);
                local_missing++;
            }
            json_object_object_add(o, "id", flowd_sqlite_text_json(st, 0));
            json_object_object_add(o, "name", flowd_sqlite_text_json(st, 1));
            json_object_object_add(o, "priority", json_object_new_int(sqlite3_column_int(st, 3)));
            json_object_object_add(o, "action", json_object_new_string(action ? action : ""));
            json_object_object_add(o, "src_object", json_object_new_string(src_object ? src_object : ""));
            json_object_object_add(o, "app_object", json_object_new_string(app_object ? app_object : ""));
            json_object_object_add(o, "time_object", json_object_new_string(time_object ? time_object : ""));
            json_object_object_add(o, "route_group", json_object_new_string(route_group ? route_group : ""));
            json_object_object_add(o, "qos_class", json_object_new_string(qos_class ? qos_class : ""));
            json_object_object_add(o, "mark", flowd_sqlite_text_json(st, 10));
            json_object_object_add(o, "log_event", json_object_new_boolean(sqlite3_column_int(st, 11)));
            json_object_object_add(o, "runtime_kind", json_object_new_string("app_policy_rule"));
            json_object_object_add(o, "state_store", json_object_new_string(FLOWD_DEFAULT_FLOW_DB_PATH));
            json_object_object_add(o, "state", json_object_new_string(local_missing ? "blocked" : "planned"));
            json_object_object_add(o, "missing_refs", missing);
            json_object_object_add(o, "mutates_dataplane", json_object_new_boolean(0));
            json_object_array_add(rules, o);
            missing_refs += local_missing;
            enabled_count++;
        }
        sqlite3_finalize(st);
    }
    json_object_object_add(out, "total", json_object_new_int(flowd_count_sql("SELECT COUNT(*) FROM flowd_app_rules")));
    json_object_object_add(out, "enabled", json_object_new_int(enabled_count));
    json_object_object_add(out, "missing_refs", json_object_new_int(missing_refs));
    json_object_object_add(out, "rules", rules);
    return missing_refs;
}

static int flowd_table_exists(const char *name)
{
    sqlite3_stmt *st;
    int exists = 0;

    if (!flowd_token_ok(name, 64))
        return 0;
    st = flowd_config_prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1 LIMIT 1");
    if (!st)
        return 0;
    sqlite3_bind_text(st, 1, name, -1, SQLITE_TRANSIENT);
    exists = sqlite3_step(st) == SQLITE_ROW;
    sqlite3_finalize(st);
    return exists ? 1 : 0;
}

static int flowd_table_count(const char *name)
{
    char sql[160];

    if (!flowd_table_exists(name))
        return 0;
    snprintf(sql, sizeof(sql), "SELECT COUNT(*) FROM %s", name);
    return flowd_count_sql(sql);
}

static void flowd_add_table_state(struct json_object *tables, const char *name)
{
    struct json_object *o = json_object_new_object();
    int present = flowd_table_exists(name);

    json_object_object_add(o, "present", json_object_new_boolean(present));
    json_object_object_add(o, "rows", json_object_new_int(present ? flowd_table_count(name) : 0));
    json_object_object_add(tables, name, o);
}

static void flowd_add_plan_step(struct json_object *steps, const char *id,
                                const char *state, const char *detail,
                                int mutates_dataplane)
{
    struct json_object *o = json_object_new_object();

    json_object_object_add(o, "id", json_object_new_string(id ? id : ""));
    json_object_object_add(o, "state", json_object_new_string(state ? state : "planned"));
    json_object_object_add(o, "detail", json_object_new_string(detail ? detail : ""));
    json_object_object_add(o, "mutates_dataplane", json_object_new_boolean(mutates_dataplane));
    json_object_array_add(steps, o);
}

static const char *flowd_compile_state_for(int enabled_count, int missing_refs)
{
    if (enabled_count <= 0)
        return "idle";
    if (missing_refs > 0)
        return "blocked";
    return "compile-ready";
}

static void flowd_add_dryrun_artifact(struct json_object *arr, const char *id,
                                      const char *kind, const char *backend,
                                      const char *resource, int planned_count,
                                      const char *state, const char *depends_on,
                                      const char *detail)
{
    struct json_object *o = json_object_new_object();

    json_object_object_add(o, "id", json_object_new_string(id ? id : ""));
    json_object_object_add(o, "kind", json_object_new_string(kind ? kind : ""));
    json_object_object_add(o, "backend", json_object_new_string(backend ? backend : ""));
    json_object_object_add(o, "resource", json_object_new_string(resource ? resource : ""));
    json_object_object_add(o, "planned_count", json_object_new_int(planned_count));
    json_object_object_add(o, "state", json_object_new_string(state ? state : "planned"));
    json_object_object_add(o, "depends_on", json_object_new_string(depends_on ? depends_on : ""));
    json_object_object_add(o, "executor", json_object_new_string("missing"));
    json_object_object_add(o, "mutates_dataplane", json_object_new_boolean(0));
    json_object_object_add(o, "detail", json_object_new_string(detail ? detail : ""));
    json_object_array_add(arr, o);
}

static void flowd_build_dataplane_artifacts(struct json_object *out,
                                            int enabled_object_count,
                                            int enabled_custom_protocol_count,
                                            int enabled_route_group_count,
                                            int enabled_wan_capacity_count,
                                            int enabled_wan_health_count,
                                            int enabled_policy_count,
                                            int geoip_missing,
                                            int enabled_split_rule_count,
                                            int split_missing_refs,
                                            int enabled_domain_rule_count,
                                            int domain_missing_refs,
                                            int enabled_qos_class_count,
                                            int enabled_qos_rule_count,
                                            int qos_missing_refs,
                                            int enabled_smart_qos_count,
                                            int smart_qos_missing_refs,
                                            int enabled_quota_rule_count,
                                            int quota_missing_refs,
                                            int enabled_conn_limit_rule_count,
                                            int conn_limit_missing_refs,
                                            int enabled_app_rule_count,
                                            int app_policy_missing_refs,
                                            int content_domain_entries,
                                            int reputation_ip_entries,
                                            int reputation_domain_entries,
                                            int reputation_url_entries)
{
    struct json_object *summary = json_object_new_object();
    struct json_object *nftables = json_object_new_array();
    struct json_object *tc = json_object_new_array();
    struct json_object *routing = json_object_new_array();
    struct json_object *dns = json_object_new_array();
    struct json_object *runtime_state = json_object_new_array();
    int reputation_entries = reputation_ip_entries + reputation_domain_entries +
                             reputation_url_entries;
    int nft_count = enabled_object_count + enabled_policy_count + enabled_split_rule_count +
                    enabled_domain_rule_count + enabled_quota_rule_count +
                    enabled_conn_limit_rule_count + enabled_app_rule_count +
                    reputation_ip_entries;
    int tc_count = enabled_wan_capacity_count + enabled_qos_class_count +
                   enabled_qos_rule_count + enabled_smart_qos_count;
    int routing_count = enabled_route_group_count + enabled_policy_count +
                        enabled_split_rule_count + enabled_domain_rule_count +
                        enabled_app_rule_count;
    int runtime_count = enabled_wan_health_count + enabled_quota_rule_count +
                        enabled_qos_rule_count + enabled_smart_qos_count +
                        enabled_app_rule_count + reputation_entries;

    json_object_object_add(summary, "nftables", json_object_new_int(nft_count));
    json_object_object_add(summary, "tc", json_object_new_int(tc_count));
    json_object_object_add(summary, "routing", json_object_new_int(routing_count));
    json_object_object_add(summary, "dns", json_object_new_int(enabled_domain_rule_count + content_domain_entries + reputation_domain_entries));
    json_object_object_add(summary, "runtime_state", json_object_new_int(runtime_count));
    json_object_object_add(summary, "content_domain_entries", json_object_new_int(content_domain_entries));
    json_object_object_add(summary, "reputation_entries", json_object_new_int(reputation_entries));
    json_object_object_add(summary, "custom_protocols", json_object_new_int(enabled_custom_protocol_count));
    json_object_object_add(summary, "executor_ready", json_object_new_boolean(0));

    flowd_add_dryrun_artifact(nftables, "object_sets", "set", "nftables",
                              "inet dreamingwrt_flow object sets", enabled_object_count,
                              flowd_compile_state_for(enabled_object_count, 0),
                              "flowd_objects",
                              "Reusable IP/MAC/port/time/domain/app/country/ISP objects for later nft set materialization");
    flowd_add_dryrun_artifact(nftables, "country_sets", "set", "nftables",
                              "inet dreamingwrt_flow GeoIP country sets", enabled_policy_count,
                              flowd_compile_state_for(enabled_policy_count, geoip_missing),
                              "dreamingwrt_signatures.db:geoip_country_prefix",
                              "Country-routing match sets derived from signature DB GeoIP country prefixes");
    flowd_add_dryrun_artifact(nftables, "split_rule_marks", "chain", "nftables",
                              "inet dreamingwrt_flow split-route mark chains", enabled_split_rule_count,
                              flowd_compile_state_for(enabled_split_rule_count, split_missing_refs),
                              "flowd_split_rules, flowd_objects, flowd_route_groups",
                              "Five-tuple/source/app/country/ISP split-routing packet marking");
    flowd_add_dryrun_artifact(nftables, "app_policy_rules", "chain", "nftables",
                              "inet dreamingwrt_flow app policy chains", enabled_app_rule_count,
                              flowd_compile_state_for(enabled_app_rule_count, app_policy_missing_refs),
                              "flowd_app_rules, signature app ids",
                              "Application/category accept/drop/route/qos/mark policy matching");
    flowd_add_dryrun_artifact(nftables, "quota_enforcement", "chain", "nftables",
                              "inet dreamingwrt_flow quota enforcement chains", enabled_quota_rule_count,
                              flowd_compile_state_for(enabled_quota_rule_count, quota_missing_refs),
                              "flowd_quota_rules, flow.db quota state",
                              "Quota/cap rule enforcement after runtime counters exist");
    flowd_add_dryrun_artifact(nftables, "connection_limits", "chain", "nftables",
                              "inet dreamingwrt_flow connection-limit chains", enabled_conn_limit_rule_count,
                              flowd_compile_state_for(enabled_conn_limit_rule_count, conn_limit_missing_refs),
                              "flowd_conn_limit_rules, conntrack",
                              "Per-object connection-limit matching and enforcement");
    flowd_add_dryrun_artifact(nftables, "domain_route_sets", "set", "nftables",
                              "inet dreamingwrt_flow domain-route sets", enabled_domain_rule_count,
                              flowd_compile_state_for(enabled_domain_rule_count, domain_missing_refs),
                              "flowd_domain_rules, resolver domain feed",
                              "Domain route result sets consumed by packet marking");
    flowd_add_dryrun_artifact(nftables, "reputation_ip_sets", "set", "nftables",
                              "inet dreamingwrt_flow reputation IP sets", reputation_ip_entries,
                              flowd_compile_state_for(reputation_ip_entries, 0),
                              "dreamingwrt_signatures.db:reputation_ip_entry",
                              "Reputation IP match sets for later block/mark/log policy consumption");

    flowd_add_dryrun_artifact(tc, "wan_shapers", "qdisc", "tc",
                              "WAN qdisc roots and shaper classes", enabled_wan_capacity_count,
                              flowd_compile_state_for(enabled_wan_capacity_count, 0),
                              "flowd_wan_capacity",
                              "Per-WAN capacity/headroom profiles for later cake/fq_codel/htb setup");
    flowd_add_dryrun_artifact(tc, "qos_classes", "class", "tc",
                              "QoS classes", enabled_qos_class_count,
                              flowd_compile_state_for(enabled_qos_class_count, qos_missing_refs),
                              "flowd_qos_classes",
                              "Traffic classes with priority, guarantee, ceiling, latency, and DSCP metadata");
    flowd_add_dryrun_artifact(tc, "qos_filters", "filter", "tc",
                              "QoS filters", enabled_qos_rule_count,
                              flowd_compile_state_for(enabled_qos_rule_count, qos_missing_refs),
                              "flowd_qos_rules, flowd_objects, flowd_qos_classes",
                              "Rule-to-class filters for source/destination/app/service/time matches");
    flowd_add_dryrun_artifact(tc, "smart_qos_category_filters", "filter", "tc",
                              "Smart QoS category filters", enabled_smart_qos_count,
                              flowd_compile_state_for(enabled_smart_qos_count, smart_qos_missing_refs),
                              "flowd_smart_qos_categories, signature categories",
                              "DPI-assisted category priority mapping to QoS classes");

    flowd_add_dryrun_artifact(routing, "route_groups", "route-table", "iproute2",
                              "per-WAN/per-group route tables", enabled_route_group_count,
                              flowd_compile_state_for(enabled_route_group_count, 0),
                              "flowd_route_groups",
                              "Weighted, primary/backup, PCC, and failover route-group tables");
    flowd_add_dryrun_artifact(routing, "fwmark_policy_rules", "ip-rule", "iproute2",
                              "fwmark policy rules", routing_count,
                              flowd_compile_state_for(routing_count, split_missing_refs + domain_missing_refs + app_policy_missing_refs + geoip_missing),
                              "country, split, domain, app policy marks",
                              "fwmark to route-table rules for policy routing");

    flowd_add_dryrun_artifact(dns, "domain_route_feed", "resolver-feed", "dns",
                              "domain-route resolver materialization", enabled_domain_rule_count,
                              flowd_compile_state_for(enabled_domain_rule_count, domain_missing_refs),
                              "flowd_domain_rules, domain objects",
                              "Domain rule feed for resolver/ipset/nft set updates");
    flowd_add_dryrun_artifact(dns, "content_category_feed", "resolver-feed", "dns",
                              "content category resolver materialization", content_domain_entries,
                              flowd_compile_state_for(content_domain_entries, 0),
                              "dreamingwrt_signatures.db:content_domain_entry",
                              "Content-category domain feed for later category filter and policy-route integration");
    flowd_add_dryrun_artifact(dns, "reputation_domain_feed", "resolver-feed", "dns",
                              "reputation domain resolver materialization", reputation_domain_entries,
                              flowd_compile_state_for(reputation_domain_entries, 0),
                              "dreamingwrt_signatures.db:reputation_domain_entry",
                              "Reputation domain feed for later block/mark/log policy consumption");
    flowd_add_dryrun_artifact(dns, "reputation_url_feed", "resolver-feed", "dns",
                              "reputation URL feed planning", reputation_url_entries,
                              flowd_compile_state_for(reputation_url_entries, 0),
                              "dreamingwrt_signatures.db:reputation_url_entry",
                              "URL reputation feed for later proxy/DPI-assisted enforcement; resolver-only backends cannot consume full URLs");

    flowd_add_dryrun_artifact(runtime_state, "flow_db", "sqlite", "runtime",
                              FLOWD_DEFAULT_FLOW_DB_PATH, runtime_count,
                              flowd_compile_state_for(runtime_count, 0),
                              "flow sampler/executor",
                              "Runtime counters, health samples, quota state, app cache, category stats, and rule hits");
    flowd_add_dryrun_artifact(runtime_state, "wan_health_samples", "sqlite", "runtime",
                              "flowd_wan_health_status and flowd_wan_health_samples", enabled_wan_health_count,
                              flowd_compile_state_for(enabled_wan_health_count, 0),
                              "flowd_wan_health",
                              "WAN health-check status and samples for failover decisions");
    flowd_add_dryrun_artifact(runtime_state, "quota_state", "sqlite", "runtime",
                              "flowd_quota_state", enabled_quota_rule_count,
                              flowd_compile_state_for(enabled_quota_rule_count, quota_missing_refs),
                              "flowd_quota_rules",
                              "Quota usage counters and period reset state");
    flowd_add_dryrun_artifact(runtime_state, "dpi_cache", "sqlite", "runtime",
                              "flowd_dpi_cache", enabled_app_rule_count + enabled_smart_qos_count,
                              flowd_compile_state_for(enabled_app_rule_count + enabled_smart_qos_count,
                                                       app_policy_missing_refs + smart_qos_missing_refs),
                              "signature DB and DPI classifier",
                              "Live app/category identification cache for policy, QoS, and diagnostics");
    flowd_add_dryrun_artifact(runtime_state, "risk_cache", "sqlite", "runtime",
                              "flowd_risk_cache", reputation_entries,
                              flowd_compile_state_for(reputation_entries, 0),
                              "dreamingwrt_signatures.db:reputation_*",
                              "Runtime reputation/risk cache for logd, identityd, and future policy decisions");

    json_object_object_add(out, "summary", summary);
    json_object_object_add(out, "nftables", nftables);
    json_object_object_add(out, "tc", tc);
    json_object_object_add(out, "routing", routing);
    json_object_object_add(out, "dns", dns);
    json_object_object_add(out, "runtime_state", runtime_state);
}

static int flowd_apply_job_save(const char *id, const char *kind,
                                const char *requested_by, int dry_run,
                                const char *plan_path, struct json_object *plan,
                                const char *state, const char *error)
{
    sqlite3_stmt *st;
    const char *plan_s;
    int64_t now = flowd_now_s();
    int ok = 0;

    if (!flowd_id_ok(id) || !flowd_token_ok(kind, 48) ||
        !flowd_text_ok(requested_by, 128) ||
        !flowd_path_ok(plan_path ? plan_path : "") || !plan)
        return -1;
    plan_s = json_object_to_json_string_ext(plan, JSON_C_TO_STRING_PLAIN);
    if (!plan_s)
        return -1;
    st = flowd_config_prepare(
        "INSERT INTO flowd_apply_jobs"
        "(id,kind,requested_by,state,dry_run,plan_path,plan_json,error,created_at,updated_at,completed_at) "
        "VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?9,?10) "
        "ON CONFLICT(id) DO UPDATE SET kind=excluded.kind,requested_by=excluded.requested_by,state=excluded.state,"
        "dry_run=excluded.dry_run,plan_path=excluded.plan_path,plan_json=excluded.plan_json,"
        "error=excluded.error,updated_at=excluded.updated_at,completed_at=excluded.completed_at");
    if (st) {
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, kind, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 3, requested_by ? requested_by : "", -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 4, state ? state : "compiled", -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 5, dry_run ? 1 : 0);
        sqlite3_bind_text(st, 6, plan_path ? plan_path : "", -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 7, plan_s, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 8, error ? error : "", -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 9, now);
        sqlite3_bind_int64(st, 10,
                           state && !strcmp(state, "applying") ? 0 : now);
        ok = sqlite3_step(st) == SQLITE_DONE;
        sqlite3_finalize(st);
    }
    return ok ? 0 : -1;
}

static void flowd_apply_job_row_json(struct json_object *arr, sqlite3_stmt *st,
                                     int include_plan)
{
    const char *plan_s = (const char *)sqlite3_column_text(st, 6);
    struct json_object *o = json_object_new_object();

    json_object_object_add(o, "id", flowd_sqlite_text_json(st, 0));
    json_object_object_add(o, "kind", flowd_sqlite_text_json(st, 1));
    json_object_object_add(o, "requested_by", flowd_sqlite_text_json(st, 2));
    json_object_object_add(o, "state", flowd_sqlite_text_json(st, 3));
    json_object_object_add(o, "dry_run", json_object_new_boolean(sqlite3_column_int(st, 4)));
    json_object_object_add(o, "plan_path", flowd_sqlite_text_json(st, 5));
    json_object_object_add(o, "error", flowd_sqlite_text_json(st, 7));
    json_object_object_add(o, "created_at", json_object_new_int64(sqlite3_column_int64(st, 8)));
    json_object_object_add(o, "updated_at", json_object_new_int64(sqlite3_column_int64(st, 9)));
    json_object_object_add(o, "completed_at", json_object_new_int64(sqlite3_column_int64(st, 10)));
    if (include_plan)
        json_object_object_add(o, "plan", flowd_json_parse_or_object(plan_s));
    json_object_array_add(arr, o);
}

static void flowd_nft_result_add(struct json_object *plan,
                                 const struct flowd_nft_apply_result *result)
{
    struct json_object *evidence = json_object_new_object();

    json_object_object_add(evidence, "validation_ok",
                           json_object_new_boolean(result->validated));
    json_object_object_add(evidence, "apply_command_ok",
                           json_object_new_boolean(result->applied));
    json_object_object_add(evidence, "revision_readback_ok",
                           json_object_new_boolean(result->readback_ok));
    json_object_object_add(evidence, "rollback_attempted",
                           json_object_new_boolean(result->rolled_back));
    json_object_object_add(evidence, "rollback_readback_ok",
                           json_object_new_boolean(result->rollback_ok));
    json_object_object_add(evidence, "previous_present",
                           json_object_new_boolean(result->previous_present));
    json_object_object_add(evidence, "previous_revision",
                           json_object_new_string(result->previous_revision));
    json_object_object_add(evidence, "apply_path",
                           json_object_new_string(result->apply_path));
    json_object_object_add(evidence, "rollback_path",
                           json_object_new_string(result->rollback_path));
    json_object_object_add(evidence, "error",
                           json_object_new_string(result->error));
    json_object_object_add(plan, "evidence", evidence);
}

struct json_object *flowd_nft_revision_status(void)
{
    struct flowd_settings settings;
    struct flowd_nft_readback readback;
    struct json_object *resp = json_object_new_object();
    const char *error = "";
    int available = 0;

    memset(&readback, 0, sizeof(readback));
    if (flowd_settings_load(&settings) != 0) {
        error = "settings_unavailable";
    } else if (access(FLOWD_NFT_BINARY, X_OK) != 0) {
        error = "nft_binary_unavailable";
    } else if (!flowd_dir_exists(settings.runtime_dir)) {
        error = "runtime_dir_unavailable";
    } else if (flowd_nft_readback(FLOWD_NFT_BINARY, settings.runtime_dir,
                                  "status", &readback) != 0) {
        error = readback.error[0] ? readback.error : "nft_revision_readback_failed";
    } else {
        available = 1;
    }

    json_object_object_add(resp, "ok", json_object_new_boolean(available));
    json_object_object_add(resp, "available", json_object_new_boolean(available));
    json_object_object_add(resp, "source", json_object_new_string("nft-json-readback"));
    json_object_object_add(resp, "table_family", json_object_new_string("inet"));
    json_object_object_add(resp, "table_name", json_object_new_string(FLOWD_NFT_TABLE));
    json_object_object_add(resp, "present",
                           json_object_new_boolean(available && readback.present));
    json_object_object_add(resp, "ownership_verified",
                           json_object_new_boolean(available && readback.present &&
                                                   readback.sentinel_only));
    json_object_object_add(resp, "sentinel_only",
                           json_object_new_boolean(available && readback.present &&
                                                   readback.sentinel_only));
    json_object_object_add(resp, "revision",
                           json_object_new_string(available ? readback.revision : ""));
    json_object_object_add(resp, "contains_policy_rules", json_object_new_boolean(0));
    json_object_object_add(resp, "runtime_applied", json_object_new_boolean(0));
    json_object_object_add(resp, "runtime_reason",
                           json_object_new_string(FLOWD_APPLY_UNAVAILABLE_REASON));
    json_object_object_add(resp, "observed_at", json_object_new_int64(flowd_now_s()));
    if (error[0])
        json_object_object_add(resp, "error", json_object_new_string(error));
    return resp;
}

struct json_object *flowd_nft_revision_apply(struct json_object *body)
{
    struct flowd_settings settings;
    struct flowd_nft_apply_result result;
    struct json_object *resp = NULL;
    struct json_object *plan = NULL;
    const char *requested_by;
    const char *requested_revision;
    const char *state;
    const char *error = "";
    char job_id[FLOWD_MAX_ID];
    char revision[128];
    int dry_run;
    int saved;
    int rc = -1;

    if (flowd_settings_load(&settings) != 0)
        return flowd_error("settings_unavailable", "flowd settings are unavailable");
    if (!body || !json_object_is_type(body, json_type_object))
        body = NULL;
    requested_by = flowd_json_str(body, "requested_by", "api");
    requested_revision = flowd_json_str(body, "revision", "");
    dry_run = flowd_json_bool(body, "dry_run", 1);
    if (!flowd_text_ok(requested_by, 128))
        return flowd_error("invalid_requested_by", "invalid flowd apply actor");
    if (requested_revision[0]) {
        if (!flowd_nft_safe_token(requested_revision, 120))
            return flowd_error("invalid_revision", "invalid nft revision token");
        snprintf(revision, sizeof(revision), "%s", requested_revision);
    } else {
        flowd_make_id("nft-revision", revision, sizeof(revision));
    }
    flowd_make_id("nft-apply", job_id, sizeof(job_id));

    plan = json_object_new_object();
    json_object_object_add(plan, "version", json_object_new_int(1));
    json_object_object_add(plan, "kind", json_object_new_string("nft_revision_apply"));
    json_object_object_add(plan, "job_id", json_object_new_string(job_id));
    json_object_object_add(plan, "revision", json_object_new_string(revision));
    json_object_object_add(plan, "generated_at", json_object_new_int64(flowd_now_s()));
    json_object_object_add(plan, "dry_run", json_object_new_boolean(dry_run));
    json_object_object_add(plan, "sentinel_only", json_object_new_boolean(1));
    json_object_object_add(plan, "contains_policy_rules", json_object_new_boolean(0));
    json_object_object_add(plan, "applies_dataplane", json_object_new_boolean(0));
    json_object_object_add(plan, "mutates_nft_sentinel", json_object_new_boolean(!dry_run));
    json_object_object_add(plan, "nft_table", json_object_new_string(FLOWD_NFT_TABLE));
    json_object_object_add(plan, "note", json_object_new_string(
        "bounded ownership/revision sentinel only; no flow, qos, route, quota, or policy rule is applied"));

    if (dry_run) {
        struct json_object *evidence = json_object_new_object();

        state = "planned";
        json_object_object_add(evidence, "validation_ok", json_object_new_boolean(0));
        json_object_object_add(evidence, "apply_command_ok", json_object_new_boolean(0));
        json_object_object_add(evidence, "revision_readback_ok", json_object_new_boolean(0));
        json_object_object_add(evidence, "not_run_reason",
                               json_object_new_string("dry_run"));
        json_object_object_add(plan, "evidence", evidence);
        saved = flowd_apply_job_save(job_id, "nft_revision_apply", requested_by,
                                     1, "", plan, state, "") == 0;
        if (!saved) {
            error = "job_save_failed";
            state = "failed";
        }
    } else {
        if (flowd_mkdir_p(settings.runtime_dir, 0755) != 0) {
            error = "runtime_dir_unavailable";
            state = "failed";
            saved = flowd_apply_job_save(job_id, "nft_revision_apply", requested_by,
                                         0, "", plan, state, error) == 0;
        } else {
            state = "applying";
            saved = flowd_apply_job_save(job_id, "nft_revision_apply", requested_by,
                                         0, "", plan, state, "") == 0;
            if (!saved) {
                error = "job_save_failed";
                state = "failed";
            } else {
                rc = flowd_nft_apply_revision(FLOWD_NFT_BINARY,
                                              settings.runtime_dir,
                                              revision, &result);
                flowd_nft_result_add(plan, &result);
                if (rc == 0) {
                    state = "applied";
                } else {
                    error = result.error[0] ? result.error : "nft_revision_apply_failed";
                    if (result.rolled_back && result.rollback_ok)
                        state = "rolled_back";
                    else
                        state = "failed";
                }
                saved = flowd_apply_job_save(job_id, "nft_revision_apply",
                                             requested_by, 0,
                                             result.apply_path, plan,
                                             state, error) == 0;
                if (!saved) {
                    error = "job_terminal_save_failed";
                    state = "failed";
                }
            }
        }
    }

    resp = json_object_new_object();
    json_object_object_add(resp, "ok",
                           json_object_new_boolean(saved && (dry_run || rc == 0)));
    json_object_object_add(resp, "job_id", json_object_new_string(job_id));
    json_object_object_add(resp, "revision", json_object_new_string(revision));
    json_object_object_add(resp, "state", json_object_new_string(state));
    json_object_object_add(resp, "dry_run", json_object_new_boolean(dry_run));
    json_object_object_add(resp, "recorded", json_object_new_boolean(saved));
    json_object_object_add(resp, "sentinel_only", json_object_new_boolean(1));
    json_object_object_add(resp, "sentinel_applied",
                           json_object_new_boolean(!dry_run && rc == 0));
    json_object_object_add(resp, "applied", json_object_new_boolean(0));
    json_object_object_add(resp, "runtime_applied", json_object_new_boolean(0));
    json_object_object_add(resp, "runtime_reason",
                           json_object_new_string(FLOWD_APPLY_UNAVAILABLE_REASON));
    json_object_object_add(resp, "plan", plan);
    if (error[0])
        json_object_object_add(resp, "error", json_object_new_string(error));
    return resp;
}

struct json_object *flowd_apply_jobs_json(struct json_object *body)
{
    sqlite3_stmt *st = NULL;
    struct json_object *resp = json_object_new_object();
    struct json_object *jobs = json_object_new_array();
    const char *id = flowd_json_str(body, "id", "");
    int include_plan = flowd_json_bool(body, "include_plan", 0);
    int limit = flowd_json_int(body, "limit", 20);
    int ok = 1;
    int total_ok = 0;
    int total;
    int rc;
    const char *error = "";

    if (id && id[0] && !flowd_id_ok(id))
        return flowd_error("invalid_id", "invalid flowd apply job id");
    if (limit < 1)
        limit = 20;
    if (limit > 100)
        limit = 100;

    if (id && id[0]) {
        st = flowd_config_prepare(
            "SELECT id,kind,requested_by,state,dry_run,plan_path,plan_json,error,created_at,updated_at,completed_at "
            "FROM flowd_apply_jobs WHERE id=?1");
        if (st)
            sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    } else {
        st = flowd_config_prepare(
            "SELECT id,kind,requested_by,state,dry_run,plan_path,plan_json,error,created_at,updated_at,completed_at "
            "FROM flowd_apply_jobs ORDER BY created_at DESC,id DESC LIMIT ?1");
        if (st)
            sqlite3_bind_int(st, 1, limit);
    }
    if (st) {
        while ((rc = sqlite3_step(st)) == SQLITE_ROW)
            flowd_apply_job_row_json(jobs, st, include_plan);
        if (rc != SQLITE_DONE) {
            ok = 0;
            error = "apply_jobs_unavailable";
        }
        sqlite3_finalize(st);
    } else {
        ok = 0;
        error = "apply_jobs_unavailable";
    }

    total = flowd_count_sql_checked("SELECT COUNT(*) FROM flowd_apply_jobs", &total_ok);
    if (!total_ok) {
        ok = 0;
        if (!error[0])
            error = "apply_jobs_count_unavailable";
    }
    json_object_object_add(resp, "ok", json_object_new_boolean(ok));
    json_object_object_add(resp, "total", json_object_new_int(total));
    json_object_object_add(resp, "jobs", jobs);
    if (error[0])
        json_object_object_add(resp, "error", json_object_new_string(error));
    return resp;
}

static sqlite3 *flowd_runtime_open_existing(const char **error)
{
    sqlite3 *db = NULL;

    if (error)
        *error = NULL;
    if (!flowd_file_exists(FLOWD_DEFAULT_FLOW_DB_PATH)) {
        if (error)
            *error = "runtime_db_missing";
        return NULL;
    }
    if (sqlite3_open_v2(FLOWD_DEFAULT_FLOW_DB_PATH, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
        fprintf(stderr, "[dreamingwrt-flowd] open runtime db failed: %s path=%s\n",
                db ? sqlite3_errmsg(db) : "sqlite open failed", FLOWD_DEFAULT_FLOW_DB_PATH);
        if (db)
            sqlite3_close(db);
        if (error)
            *error = "runtime_db_open_failed";
        return NULL;
    }
    sqlite3_busy_timeout(db, 1000);
    return db;
}

static int flowd_runtime_table_exists_checked(sqlite3 *db, const char *name, int *ok)
{
    sqlite3_stmt *st;
    int exists = 0;
    int rc;

    if (ok)
        *ok = 0;
    if (!db || !flowd_token_ok(name, 64))
        return 0;
    if (sqlite3_prepare_v2(db, "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1 LIMIT 1", -1, &st, NULL) != SQLITE_OK) {
        fprintf(stderr, "[dreamingwrt-flowd] runtime table probe prepare failed: %s table=%s\n",
                sqlite3_errmsg(db), name ? name : "");
        return 0;
    }
    sqlite3_bind_text(st, 1, name, -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(st);
    if (rc == SQLITE_ROW || rc == SQLITE_DONE) {
        exists = rc == SQLITE_ROW;
        if (ok)
            *ok = 1;
    } else {
        fprintf(stderr, "[dreamingwrt-flowd] runtime table probe failed: %s table=%s\n",
                sqlite3_errmsg(db), name ? name : "");
    }
    sqlite3_finalize(st);
    return exists;
}

static int flowd_runtime_count_checked(sqlite3 *db, const char *table, int *ok)
{
    char sql[128];
    sqlite3_stmt *st;
    int count = 0;
    int table_ok = 0;
    int rc;

    if (ok)
        *ok = 0;
    if (!flowd_runtime_table_exists_checked(db, table, &table_ok) || !table_ok) {
        if (table_ok && ok)
            *ok = 1;
        return 0;
    }

    snprintf(sql, sizeof(sql), "SELECT COUNT(*) FROM %s", table);
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) {
        fprintf(stderr, "[dreamingwrt-flowd] runtime count prepare failed: %s table=%s\n",
                sqlite3_errmsg(db), table ? table : "");
        return 0;
    }
    rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) {
        count = sqlite3_column_int(st, 0);
        if (ok)
            *ok = 1;
    } else if (rc != SQLITE_DONE) {
        fprintf(stderr, "[dreamingwrt-flowd] runtime count failed: %s table=%s\n",
                sqlite3_errmsg(db), table ? table : "");
    }
    sqlite3_finalize(st);
    return count;
}

static const char *flowd_runtime_existing_table_checked(sqlite3 *db, const char *primary,
                                                       const char *legacy, int *ok)
{
    int probe_ok = 0;

    if (ok)
        *ok = 0;
    if (flowd_runtime_table_exists_checked(db, primary, &probe_ok)) {
        if (ok)
            *ok = 1;
        return primary;
    }
    if (!probe_ok)
        return NULL;
    if (legacy && flowd_runtime_table_exists_checked(db, legacy, &probe_ok)) {
        if (ok)
            *ok = 1;
        return legacy;
    }
    if (!probe_ok)
        return NULL;
    if (ok)
        *ok = 1;
    return NULL;
}

static int flowd_runtime_count_any_checked(sqlite3 *db, const char *primary, const char *legacy, int *ok)
{
    const char *table = flowd_runtime_existing_table_checked(db, primary, legacy, ok);

    if (!table) {
        return 0;
    }
    return flowd_runtime_count_checked(db, table, ok);
}

static void flowd_runtime_add_table_state(sqlite3 *db, struct json_object *tables,
                                          struct json_object *errors, int *all_ok,
                                          const char *name)
{
    int ok = 0;
    int present = flowd_runtime_table_exists_checked(db, name, &ok);

    json_object_object_add(tables, name, json_object_new_boolean(present));
    if (!ok) {
        if (all_ok)
            *all_ok = 0;
        flowd_status_error_add(errors, name, "runtime_table_probe_failed");
    }
}

static int flowd_runtime_query_rows(sqlite3 *db, const char *sql, struct json_object *arr,
                                    void (*row_fn)(struct json_object *, sqlite3_stmt *))
{
    sqlite3_stmt *st;
    int rc;

    if (!db || !sql || !arr || !row_fn)
        return -1;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) {
        fprintf(stderr, "[dreamingwrt-flowd] runtime rows prepare failed: %s sql=%s\n",
                sqlite3_errmsg(db), sql ? sql : "");
        return -1;
    }
    while ((rc = sqlite3_step(st)) == SQLITE_ROW)
        row_fn(arr, st);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) {
        fprintf(stderr, "[dreamingwrt-flowd] runtime rows query failed: %s sql=%s\n",
                sqlite3_errmsg(db), sql ? sql : "");
        return -1;
    }
    return 0;
}

static void flowd_runtime_summary_count_add(sqlite3 *db, struct json_object *summary,
                                            struct json_object *errors, int *all_ok,
                                            const char *field, const char *table)
{
    int ok = 0;
    int count = flowd_runtime_count_checked(db, table, &ok);

    json_object_object_add(summary, field, json_object_new_int(count));
    if (!ok) {
        if (all_ok)
            *all_ok = 0;
        flowd_status_error_add(errors, field, "runtime_count_failed");
    }
}

static void flowd_runtime_summary_count_any_add(sqlite3 *db, struct json_object *summary,
                                                struct json_object *errors, int *all_ok,
                                                const char *field, const char *primary,
                                                const char *legacy)
{
    int ok = 0;
    int count = flowd_runtime_count_any_checked(db, primary, legacy, &ok);

    json_object_object_add(summary, field, json_object_new_int(count));
    if (!ok) {
        if (all_ok)
            *all_ok = 0;
        flowd_status_error_add(errors, field, "runtime_count_failed");
    }
}

static int flowd_runtime_rows_add(sqlite3 *db, struct json_object *arr,
                                  struct json_object *errors, int *all_ok,
                                  const char *field, const char *sql,
                                  void (*row_fn)(struct json_object *, sqlite3_stmt *))
{
    if (flowd_runtime_query_rows(db, sql, arr, row_fn) == 0)
        return 0;
    if (all_ok)
        *all_ok = 0;
    flowd_status_error_add(errors, field, "runtime_rows_query_failed");
    return -1;
}

static int flowd_runtime_table_present_for_query(sqlite3 *db, struct json_object *errors,
                                                 int *all_ok, const char *field,
                                                 const char *table)
{
    int ok = 0;
    int present = flowd_runtime_table_exists_checked(db, table, &ok);

    if (!ok) {
        if (all_ok)
            *all_ok = 0;
        flowd_status_error_add(errors, field, "runtime_table_probe_failed");
        return 0;
    }
    return present;
}

static const char *flowd_runtime_existing_table_for_query(sqlite3 *db,
                                                          struct json_object *errors,
                                                          int *all_ok,
                                                          const char *field,
                                                          const char *primary,
                                                          const char *legacy)
{
    int ok = 0;
    const char *table = flowd_runtime_existing_table_checked(db, primary, legacy, &ok);

    if (!ok) {
        if (all_ok)
            *all_ok = 0;
        flowd_status_error_add(errors, field, "runtime_table_probe_failed");
    }
    return table;
}

static void flowd_runtime_wan_row(struct json_object *arr, sqlite3_stmt *st)
{
    struct json_object *o = json_object_new_object();
    const char *wan = (const char *)sqlite3_column_text(st, 0);

    json_object_object_add(o, "wan", json_object_new_string(wan ? wan : ""));
    json_object_object_add(o, "rx_bytes", json_object_new_int64(sqlite3_column_int64(st, 1)));
    json_object_object_add(o, "tx_bytes", json_object_new_int64(sqlite3_column_int64(st, 2)));
    json_object_object_add(o, "rx_packets", json_object_new_int64(sqlite3_column_int64(st, 3)));
    json_object_object_add(o, "tx_packets", json_object_new_int64(sqlite3_column_int64(st, 4)));
    json_object_object_add(o, "sample_ts", json_object_new_int64(sqlite3_column_int64(st, 5)));
    json_object_array_add(arr, o);
}

static void flowd_runtime_host_row(struct json_object *arr, sqlite3_stmt *st)
{
    struct json_object *o = json_object_new_object();
    const char *host = (const char *)sqlite3_column_text(st, 0);
    const char *mac = (const char *)sqlite3_column_text(st, 1);

    json_object_object_add(o, "host", json_object_new_string(host ? host : ""));
    json_object_object_add(o, "mac", json_object_new_string(mac ? mac : ""));
    json_object_object_add(o, "rx_bytes", json_object_new_int64(sqlite3_column_int64(st, 2)));
    json_object_object_add(o, "tx_bytes", json_object_new_int64(sqlite3_column_int64(st, 3)));
    json_object_object_add(o, "active_flows", json_object_new_int(sqlite3_column_int(st, 4)));
    json_object_object_add(o, "sample_ts", json_object_new_int64(sqlite3_column_int64(st, 5)));
    json_object_array_add(arr, o);
}

static void flowd_runtime_rule_row(struct json_object *arr, sqlite3_stmt *st)
{
    struct json_object *o = json_object_new_object();
    const char *rule_id = (const char *)sqlite3_column_text(st, 0);
    const char *kind = (const char *)sqlite3_column_text(st, 1);

    json_object_object_add(o, "rule_id", json_object_new_string(rule_id ? rule_id : ""));
    json_object_object_add(o, "kind", json_object_new_string(kind ? kind : ""));
    json_object_object_add(o, "hits", json_object_new_int64(sqlite3_column_int64(st, 2)));
    json_object_object_add(o, "bytes", json_object_new_int64(sqlite3_column_int64(st, 3)));
    json_object_object_add(o, "last_seen", json_object_new_int64(sqlite3_column_int64(st, 4)));
    json_object_array_add(arr, o);
}

static void flowd_runtime_app_row(struct json_object *arr, sqlite3_stmt *st)
{
    struct json_object *o = json_object_new_object();
    const char *host = (const char *)sqlite3_column_text(st, 0);
    const char *app_id = (const char *)sqlite3_column_text(st, 1);
    const char *app_name = (const char *)sqlite3_column_text(st, 2);

    json_object_object_add(o, "host", json_object_new_string(host ? host : ""));
    json_object_object_add(o, "app_id", json_object_new_string(app_id ? app_id : ""));
    json_object_object_add(o, "app_name", json_object_new_string(app_name ? app_name : ""));
    json_object_object_add(o, "rx_bytes", json_object_new_int64(sqlite3_column_int64(st, 3)));
    json_object_object_add(o, "tx_bytes", json_object_new_int64(sqlite3_column_int64(st, 4)));
    json_object_object_add(o, "last_seen", json_object_new_int64(sqlite3_column_int64(st, 5)));
    json_object_array_add(arr, o);
}

static void flowd_runtime_wan_health_status_row(struct json_object *arr, sqlite3_stmt *st)
{
    struct json_object *o = json_object_new_object();
    const char *wan = (const char *)sqlite3_column_text(st, 0);
    const char *state = (const char *)sqlite3_column_text(st, 1);
    const char *reason = (const char *)sqlite3_column_text(st, 6);

    json_object_object_add(o, "wan", json_object_new_string(wan ? wan : ""));
    json_object_object_add(o, "state", json_object_new_string(state ? state : ""));
    json_object_object_add(o, "latency_ms", json_object_new_int(sqlite3_column_int(st, 2)));
    json_object_object_add(o, "loss_pct", json_object_new_int(sqlite3_column_int(st, 3)));
    json_object_object_add(o, "last_change", json_object_new_int64(sqlite3_column_int64(st, 4)));
    json_object_object_add(o, "last_sample", json_object_new_int64(sqlite3_column_int64(st, 5)));
    json_object_object_add(o, "reason", json_object_new_string(reason ? reason : ""));
    json_object_array_add(arr, o);
}

static void flowd_runtime_wan_health_sample_row(struct json_object *arr, sqlite3_stmt *st)
{
    struct json_object *o = json_object_new_object();
    const char *wan = (const char *)sqlite3_column_text(st, 0);
    const char *method = (const char *)sqlite3_column_text(st, 1);
    const char *target = (const char *)sqlite3_column_text(st, 2);
    const char *error = (const char *)sqlite3_column_text(st, 7);

    json_object_object_add(o, "wan", json_object_new_string(wan ? wan : ""));
    json_object_object_add(o, "method", json_object_new_string(method ? method : ""));
    json_object_object_add(o, "target", json_object_new_string(target ? target : ""));
    json_object_object_add(o, "ok", json_object_new_boolean(sqlite3_column_int(st, 3)));
    json_object_object_add(o, "latency_ms", json_object_new_int(sqlite3_column_int(st, 4)));
    json_object_object_add(o, "loss_pct", json_object_new_int(sqlite3_column_int(st, 5)));
    json_object_object_add(o, "sample_ts", json_object_new_int64(sqlite3_column_int64(st, 6)));
    json_object_object_add(o, "error", json_object_new_string(error ? error : ""));
    json_object_array_add(arr, o);
}

static void flowd_runtime_global_category_row(struct json_object *arr, sqlite3_stmt *st)
{
    struct json_object *o = json_object_new_object();
    const char *category = (const char *)sqlite3_column_text(st, 0);

    json_object_object_add(o, "category", json_object_new_string(category ? category : ""));
    json_object_object_add(o, "rx_bytes", json_object_new_int64(sqlite3_column_int64(st, 1)));
    json_object_object_add(o, "tx_bytes", json_object_new_int64(sqlite3_column_int64(st, 2)));
    json_object_object_add(o, "rx_packets", json_object_new_int64(sqlite3_column_int64(st, 3)));
    json_object_object_add(o, "tx_packets", json_object_new_int64(sqlite3_column_int64(st, 4)));
    json_object_object_add(o, "active_flows", json_object_new_int(sqlite3_column_int(st, 5)));
    json_object_object_add(o, "sample_ts", json_object_new_int64(sqlite3_column_int64(st, 6)));
    json_object_array_add(arr, o);
}

static void flowd_runtime_wan_category_row(struct json_object *arr, sqlite3_stmt *st)
{
    struct json_object *o = json_object_new_object();
    const char *wan = (const char *)sqlite3_column_text(st, 0);
    const char *category = (const char *)sqlite3_column_text(st, 1);

    json_object_object_add(o, "wan", json_object_new_string(wan ? wan : ""));
    json_object_object_add(o, "category", json_object_new_string(category ? category : ""));
    json_object_object_add(o, "rx_bytes", json_object_new_int64(sqlite3_column_int64(st, 2)));
    json_object_object_add(o, "tx_bytes", json_object_new_int64(sqlite3_column_int64(st, 3)));
    json_object_object_add(o, "rx_packets", json_object_new_int64(sqlite3_column_int64(st, 4)));
    json_object_object_add(o, "tx_packets", json_object_new_int64(sqlite3_column_int64(st, 5)));
    json_object_object_add(o, "active_flows", json_object_new_int(sqlite3_column_int(st, 6)));
    json_object_object_add(o, "sample_ts", json_object_new_int64(sqlite3_column_int64(st, 7)));
    json_object_array_add(arr, o);
}

static void flowd_runtime_dpi_cache_row(struct json_object *arr, sqlite3_stmt *st)
{
    struct json_object *o = json_object_new_object();
    const char *host = (const char *)sqlite3_column_text(st, 0);
    const char *ip = (const char *)sqlite3_column_text(st, 1);
    const char *proto = (const char *)sqlite3_column_text(st, 3);
    const char *app_id = (const char *)sqlite3_column_text(st, 4);
    const char *app_name = (const char *)sqlite3_column_text(st, 5);
    const char *category = (const char *)sqlite3_column_text(st, 6);
    const char *priority = (const char *)sqlite3_column_text(st, 7);
    const char *wan = (const char *)sqlite3_column_text(st, 8);

    json_object_object_add(o, "host", json_object_new_string(host ? host : ""));
    json_object_object_add(o, "ip", json_object_new_string(ip ? ip : ""));
    json_object_object_add(o, "port", json_object_new_int(sqlite3_column_int(st, 2)));
    json_object_object_add(o, "proto", json_object_new_string(proto ? proto : ""));
    json_object_object_add(o, "app_id", json_object_new_string(app_id ? app_id : ""));
    json_object_object_add(o, "app_name", json_object_new_string(app_name ? app_name : ""));
    json_object_object_add(o, "category", json_object_new_string(category ? category : ""));
    json_object_object_add(o, "priority", json_object_new_string(priority ? priority : ""));
    json_object_object_add(o, "wan", json_object_new_string(wan ? wan : ""));
    json_object_object_add(o, "rx_bytes", json_object_new_int64(sqlite3_column_int64(st, 9)));
    json_object_object_add(o, "tx_bytes", json_object_new_int64(sqlite3_column_int64(st, 10)));
    json_object_object_add(o, "last_seen", json_object_new_int64(sqlite3_column_int64(st, 11)));
    json_object_array_add(arr, o);
}

static void flowd_runtime_quota_state_row(struct json_object *arr, sqlite3_stmt *st)
{
    struct json_object *o = json_object_new_object();
    const char *rule_id = (const char *)sqlite3_column_text(st, 0);
    const char *target = (const char *)sqlite3_column_text(st, 1);
    const char *scope = (const char *)sqlite3_column_text(st, 2);
    const char *state = (const char *)sqlite3_column_text(st, 7);

    json_object_object_add(o, "rule_id", json_object_new_string(rule_id ? rule_id : ""));
    json_object_object_add(o, "target", json_object_new_string(target ? target : ""));
    json_object_object_add(o, "scope", json_object_new_string(scope ? scope : ""));
    json_object_object_add(o, "used_bytes", json_object_new_int64(sqlite3_column_int64(st, 3)));
    json_object_object_add(o, "limit_bytes", json_object_new_int64(sqlite3_column_int64(st, 4)));
    json_object_object_add(o, "period_start", json_object_new_int64(sqlite3_column_int64(st, 5)));
    json_object_object_add(o, "period_end", json_object_new_int64(sqlite3_column_int64(st, 6)));
    json_object_object_add(o, "state", json_object_new_string(state ? state : ""));
    json_object_object_add(o, "last_seen", json_object_new_int64(sqlite3_column_int64(st, 8)));
    json_object_array_add(arr, o);
}

static void flowd_runtime_risk_cache_row(struct json_object *arr, sqlite3_stmt *st)
{
    struct json_object *o = json_object_new_object();
    const char *kind = (const char *)sqlite3_column_text(st, 0);
    const char *value = (const char *)sqlite3_column_text(st, 1);
    const char *family = (const char *)sqlite3_column_text(st, 2);
    const char *source = (const char *)sqlite3_column_text(st, 3);
    const char *severity = (const char *)sqlite3_column_text(st, 4);
    const char *action = (const char *)sqlite3_column_text(st, 6);
    const char *reason = (const char *)sqlite3_column_text(st, 12);

    json_object_object_add(o, "kind", json_object_new_string(kind ? kind : ""));
    json_object_object_add(o, "value", json_object_new_string(value ? value : ""));
    json_object_object_add(o, "family", json_object_new_string(family ? family : ""));
    json_object_object_add(o, "source", json_object_new_string(source ? source : ""));
    json_object_object_add(o, "severity", json_object_new_string(severity ? severity : ""));
    json_object_object_add(o, "confidence", json_object_new_int(sqlite3_column_int(st, 5)));
    json_object_object_add(o, "action", json_object_new_string(action ? action : ""));
    json_object_object_add(o, "hits", json_object_new_int64(sqlite3_column_int64(st, 7)));
    json_object_object_add(o, "bytes", json_object_new_int64(sqlite3_column_int64(st, 8)));
    json_object_object_add(o, "first_seen", json_object_new_int64(sqlite3_column_int64(st, 9)));
    json_object_object_add(o, "last_seen", json_object_new_int64(sqlite3_column_int64(st, 10)));
    json_object_object_add(o, "expires_at", json_object_new_int64(sqlite3_column_int64(st, 11)));
    json_object_object_add(o, "reason", json_object_new_string(reason ? reason : ""));
    json_object_array_add(arr, o);
}

struct json_object *flowd_runtime_json(struct json_object *body)
{
    struct flowd_settings settings;
    struct flowd_runtime_contract_input runtime_contract;
    sqlite3 *db;
    const char *runtime_error = NULL;
    struct json_object *resp = json_object_new_object();
    struct json_object *tables = json_object_new_object();
    struct json_object *summary = json_object_new_object();
    struct json_object *errors = json_object_new_array();
    struct json_object *wan_counters = json_object_new_array();
    struct json_object *host_counters = json_object_new_array();
    struct json_object *rule_hits = json_object_new_array();
    struct json_object *active_apps = json_object_new_array();
    struct json_object *wan_health_status = json_object_new_array();
    struct json_object *wan_health_samples = json_object_new_array();
    struct json_object *global_category_counters = json_object_new_array();
    struct json_object *wan_category_counters = json_object_new_array();
    struct json_object *dpi_cache = json_object_new_array();
    struct json_object *quota_state = json_object_new_array();
    struct json_object *risk_cache = json_object_new_array();
    int limit = flowd_json_int(body, "limit", 100);
    int ok = 1;
    int settings_available;

    settings_available = flowd_settings_load(&settings) == 0;
    runtime_contract.configured_enabled = settings.enabled;
    runtime_contract.configured_apply_mode = settings.apply_mode;
    runtime_contract.config_store_available = settings_available;
    runtime_contract.runtime_snapshot_available = 0;
    runtime_contract.nft_binary_available = access(FLOWD_NFT_BINARY, X_OK) == 0;
    runtime_contract.runtime_dir_available = flowd_dir_exists(settings.runtime_dir);

    if (limit < 1 || limit > 500)
        limit = 100;
    json_object_object_add(resp, "ok", json_object_new_boolean(1));
    json_object_object_add(resp, "settings_available",
                           json_object_new_boolean(settings_available));
    json_object_object_add(resp, "runtime_db_path", json_object_new_string(FLOWD_DEFAULT_FLOW_DB_PATH));
    db = flowd_runtime_open_existing(&runtime_error);
    if (!db) {
        int missing = runtime_error && !strcmp(runtime_error, "runtime_db_missing");

        json_object_object_add(resp, "available", json_object_new_boolean(0));
        json_object_object_add(resp, "runtime_db_present", json_object_new_boolean(0));
        json_object_object_add(resp, "ok", json_object_new_boolean(missing));
        json_object_object_add(resp, "error", json_object_new_string(runtime_error ? runtime_error : "runtime_db_unavailable"));
        json_object_object_add(resp, "message", json_object_new_string(missing ?
                               "flow runtime database does not exist yet; no sampler or dataplane executor has populated it" :
                               "flow runtime database exists but cannot be opened read-only"));
        json_object_object_add(resp, "tables", tables);
        json_object_object_add(resp, "summary", summary);
        json_object_object_add(resp, "wan_counters", wan_counters);
        json_object_object_add(resp, "host_counters", host_counters);
        json_object_object_add(resp, "rule_hits", rule_hits);
        json_object_object_add(resp, "active_apps", active_apps);
        json_object_object_add(resp, "wan_health_status", wan_health_status);
        json_object_object_add(resp, "wan_health_samples", wan_health_samples);
        json_object_object_add(resp, "global_category_counters", global_category_counters);
        json_object_object_add(resp, "wan_category_counters", wan_category_counters);
        json_object_object_add(resp, "dpi_cache", dpi_cache);
        json_object_object_add(resp, "quota_state", quota_state);
        json_object_object_add(resp, "risk_cache", risk_cache);
        flowd_runtime_contract_add(resp, &runtime_contract);
        json_object_put(errors);
        return resp;
    }

    flowd_runtime_add_table_state(db, tables, errors, &ok, "flowd_wan_counters");
    flowd_runtime_add_table_state(db, tables, errors, &ok, "flowd_host_counters");
    flowd_runtime_add_table_state(db, tables, errors, &ok, "flowd_rule_hits");
    flowd_runtime_add_table_state(db, tables, errors, &ok, "flowd_active_apps");
    flowd_runtime_add_table_state(db, tables, errors, &ok, "flowd_wan_health_status");
    flowd_runtime_add_table_state(db, tables, errors, &ok, "flowd_wan_health_samples");
    flowd_runtime_add_table_state(db, tables, errors, &ok, "flowd_global_category_counters");
    flowd_runtime_add_table_state(db, tables, errors, &ok, "flowd_wan_category_counters");
    flowd_runtime_add_table_state(db, tables, errors, &ok, "flowd_dpi_cache");
    flowd_runtime_add_table_state(db, tables, errors, &ok, "flowd_quota_state");
    flowd_runtime_add_table_state(db, tables, errors, &ok, "flowd_risk_cache");
    flowd_runtime_add_table_state(db, tables, errors, &ok, "flow_global_category_counters");
    flowd_runtime_add_table_state(db, tables, errors, &ok, "flow_wan_category_counters");
    flowd_runtime_add_table_state(db, tables, errors, &ok, "flow_dpi_cache_snapshot");
    flowd_runtime_add_table_state(db, tables, errors, &ok, "flow_quota_state");
    flowd_runtime_summary_count_add(db, summary, errors, &ok, "wan_counters", "flowd_wan_counters");
    flowd_runtime_summary_count_add(db, summary, errors, &ok, "host_counters", "flowd_host_counters");
    flowd_runtime_summary_count_add(db, summary, errors, &ok, "rule_hits", "flowd_rule_hits");
    flowd_runtime_summary_count_add(db, summary, errors, &ok, "active_apps", "flowd_active_apps");
    flowd_runtime_summary_count_add(db, summary, errors, &ok, "wan_health_status", "flowd_wan_health_status");
    flowd_runtime_summary_count_add(db, summary, errors, &ok, "wan_health_samples", "flowd_wan_health_samples");
    flowd_runtime_summary_count_any_add(db, summary, errors, &ok, "global_category_counters", "flowd_global_category_counters", "flow_global_category_counters");
    flowd_runtime_summary_count_any_add(db, summary, errors, &ok, "wan_category_counters", "flowd_wan_category_counters", "flow_wan_category_counters");
    flowd_runtime_summary_count_any_add(db, summary, errors, &ok, "dpi_cache", "flowd_dpi_cache", "flow_dpi_cache_snapshot");
    flowd_runtime_summary_count_any_add(db, summary, errors, &ok, "quota_state", "flowd_quota_state", "flow_quota_state");
    flowd_runtime_summary_count_add(db, summary, errors, &ok, "risk_cache", "flowd_risk_cache");

    if (flowd_runtime_table_present_for_query(db, errors, &ok, "wan_counters", "flowd_wan_counters"))
        flowd_runtime_rows_add(db, wan_counters, errors, &ok, "wan_counters",
            "SELECT wan,rx_bytes,tx_bytes,rx_packets,tx_packets,sample_ts FROM flowd_wan_counters ORDER BY wan LIMIT 64",
            flowd_runtime_wan_row);
    if (flowd_runtime_table_present_for_query(db, errors, &ok, "host_counters", "flowd_host_counters")) {
        char sql[192];
        snprintf(sql, sizeof(sql), "SELECT host,mac,rx_bytes,tx_bytes,active_flows,sample_ts FROM flowd_host_counters ORDER BY (rx_bytes+tx_bytes) DESC LIMIT %d", limit);
        flowd_runtime_rows_add(db, host_counters, errors, &ok, "host_counters", sql, flowd_runtime_host_row);
    }
    if (flowd_runtime_table_present_for_query(db, errors, &ok, "rule_hits", "flowd_rule_hits")) {
        char sql[192];
        snprintf(sql, sizeof(sql), "SELECT rule_id,kind,hits,bytes,last_seen FROM flowd_rule_hits ORDER BY hits DESC,last_seen DESC LIMIT %d", limit);
        flowd_runtime_rows_add(db, rule_hits, errors, &ok, "rule_hits", sql, flowd_runtime_rule_row);
    }
    if (flowd_runtime_table_present_for_query(db, errors, &ok, "active_apps", "flowd_active_apps")) {
        char sql[192];
        snprintf(sql, sizeof(sql), "SELECT host,app_id,app_name,rx_bytes,tx_bytes,last_seen FROM flowd_active_apps ORDER BY last_seen DESC LIMIT %d", limit);
        flowd_runtime_rows_add(db, active_apps, errors, &ok, "active_apps", sql, flowd_runtime_app_row);
    }
    if (flowd_runtime_table_present_for_query(db, errors, &ok, "wan_health_status", "flowd_wan_health_status"))
        flowd_runtime_rows_add(db, wan_health_status, errors, &ok, "wan_health_status",
            "SELECT wan,state,latency_ms,loss_pct,last_change,last_sample,reason FROM flowd_wan_health_status ORDER BY wan LIMIT 64",
            flowd_runtime_wan_health_status_row);
    if (flowd_runtime_table_present_for_query(db, errors, &ok, "wan_health_samples", "flowd_wan_health_samples")) {
        char sql[224];
        snprintf(sql, sizeof(sql), "SELECT wan,method,target,ok,latency_ms,loss_pct,sample_ts,error FROM flowd_wan_health_samples ORDER BY sample_ts DESC LIMIT %d", limit);
        flowd_runtime_rows_add(db, wan_health_samples, errors, &ok, "wan_health_samples", sql, flowd_runtime_wan_health_sample_row);
    }
    {
        const char *table = flowd_runtime_existing_table_for_query(db, errors, &ok, "global_category_counters", "flowd_global_category_counters", "flow_global_category_counters");
        if (table) {
            char sql[320];
            snprintf(sql, sizeof(sql), "SELECT category,rx_bytes,tx_bytes,rx_packets,tx_packets,active_flows,sample_ts FROM %s ORDER BY (rx_bytes+tx_bytes) DESC LIMIT %d", table, limit);
            flowd_runtime_rows_add(db, global_category_counters, errors, &ok, "global_category_counters", sql, flowd_runtime_global_category_row);
        }
    }
    {
        const char *table = flowd_runtime_existing_table_for_query(db, errors, &ok, "wan_category_counters", "flowd_wan_category_counters", "flow_wan_category_counters");
        if (table) {
            char sql[352];
            snprintf(sql, sizeof(sql), "SELECT wan,category,rx_bytes,tx_bytes,rx_packets,tx_packets,active_flows,sample_ts FROM %s ORDER BY wan,(rx_bytes+tx_bytes) DESC LIMIT %d", table, limit);
            flowd_runtime_rows_add(db, wan_category_counters, errors, &ok, "wan_category_counters", sql, flowd_runtime_wan_category_row);
        }
    }
    {
        const char *table = flowd_runtime_existing_table_for_query(db, errors, &ok, "dpi_cache", "flowd_dpi_cache", "flow_dpi_cache_snapshot");
        if (table) {
            char sql[416];
            snprintf(sql, sizeof(sql), "SELECT host,ip,port,proto,app_id,app_name,category,priority,wan,rx_bytes,tx_bytes,last_seen FROM %s ORDER BY last_seen DESC LIMIT %d", table, limit);
            flowd_runtime_rows_add(db, dpi_cache, errors, &ok, "dpi_cache", sql, flowd_runtime_dpi_cache_row);
        }
    }
    {
        const char *table = flowd_runtime_existing_table_for_query(db, errors, &ok, "quota_state", "flowd_quota_state", "flow_quota_state");
        if (table) {
            char sql[384];
            snprintf(sql, sizeof(sql), "SELECT rule_id,target,scope,used_bytes,limit_bytes,period_start,period_end,state,last_seen FROM %s ORDER BY last_seen DESC LIMIT %d", table, limit);
            flowd_runtime_rows_add(db, quota_state, errors, &ok, "quota_state", sql, flowd_runtime_quota_state_row);
        }
    }
    if (flowd_runtime_table_present_for_query(db, errors, &ok, "risk_cache", "flowd_risk_cache")) {
        char sql[512];
        snprintf(sql, sizeof(sql), "SELECT kind,value,family,source,severity,confidence,action,hits,bytes,first_seen,last_seen,expires_at,reason FROM flowd_risk_cache ORDER BY last_seen DESC,hits DESC LIMIT %d", limit);
        flowd_runtime_rows_add(db, risk_cache, errors, &ok, "risk_cache", sql, flowd_runtime_risk_cache_row);
    }

    sqlite3_close(db);
    flowd_response_set_ok(resp, ok);
    json_object_object_add(resp, "available", json_object_new_boolean(1));
    json_object_object_add(resp, "runtime_db_present", json_object_new_boolean(1));
    json_object_object_add(resp, "tables", tables);
    json_object_object_add(resp, "summary", summary);
    json_object_object_add(resp, "wan_counters", wan_counters);
    json_object_object_add(resp, "host_counters", host_counters);
    json_object_object_add(resp, "rule_hits", rule_hits);
    json_object_object_add(resp, "active_apps", active_apps);
    json_object_object_add(resp, "wan_health_status", wan_health_status);
    json_object_object_add(resp, "wan_health_samples", wan_health_samples);
    json_object_object_add(resp, "global_category_counters", global_category_counters);
    json_object_object_add(resp, "wan_category_counters", wan_category_counters);
    json_object_object_add(resp, "dpi_cache", dpi_cache);
    json_object_object_add(resp, "quota_state", quota_state);
    json_object_object_add(resp, "risk_cache", risk_cache);
    if (json_object_array_length(errors) > 0)
        json_object_object_add(resp, "errors", errors);
    else
        json_object_put(errors);
    json_object_object_add(resp, "note", json_object_new_string("read-only runtime snapshot; empty or missing tables mean the sampler/executor has not populated flow.db yet"));
    runtime_contract.runtime_snapshot_available = 1;
    flowd_runtime_contract_add(resp, &runtime_contract);
    return resp;
}

struct json_object *flowd_compile(struct json_object *body)
{
    struct flowd_settings s;
    sqlite3_stmt *st;
    struct json_object *resp = json_object_new_object();
    struct json_object *plan = json_object_new_object();
    struct json_object *inputs = json_object_new_object();
    struct json_object *objects = json_object_new_object();
    struct json_object *custom_protocols = json_object_new_object();
    struct json_object *route_groups = json_object_new_object();
    struct json_object *wan_capacity = json_object_new_object();
    struct json_object *wan_health = json_object_new_object();
    struct json_object *split_rules = json_object_new_object();
    struct json_object *domain_rules = json_object_new_object();
    struct json_object *qos = json_object_new_object();
    struct json_object *smart_qos = json_object_new_object();
    struct json_object *quota = json_object_new_object();
    struct json_object *conn_limit = json_object_new_object();
    struct json_object *app_policy = json_object_new_object();
    struct json_object *country = json_object_new_object();
    struct json_object *policies = json_object_new_array();
    struct json_object *country_prefix_index = NULL;
    struct json_object *country_sets = NULL;
    struct json_object *signature_datasets = NULL;
    struct json_object *legacy = json_object_new_object();
    struct json_object *legacy_tables = json_object_new_object();
    struct json_object *steps = json_object_new_array();
    struct json_object *blockers = json_object_new_array();
    struct json_object *warnings = json_object_new_array();
    struct json_object *dataplane_artifacts = json_object_new_object();
    char job_id[FLOWD_MAX_ID];
    char plan_leaf[FLOWD_MAX_ID + 8];
    char plan_path[FLOWD_MAX_TEXT + FLOWD_MAX_ID + 32];
    const char *requested_by;
    const char *scope;
    int write_plan;
    int record_job;
    int dry_run;
    int written = 0;
    int saved = 0;
    int policy_count = 0;
    int enabled_policy_count = 0;
    int enabled_object_count = 0;
    int enabled_route_group_count = 0;
    int enabled_wan_capacity_count = 0;
    int enabled_wan_health_count = 0;
    int enabled_split_rule_count = 0;
    int enabled_domain_rule_count = 0;
    int enabled_custom_protocol_count = 0;
    int enabled_qos_class_count = 0;
    int enabled_qos_rule_count = 0;
    int enabled_smart_qos_count = 0;
    int enabled_quota_rule_count = 0;
    int enabled_conn_limit_rule_count = 0;
    int enabled_app_rule_count = 0;
    int content_domain_entries = 0;
    int reputation_ip_entries = 0;
    int reputation_domain_entries = 0;
    int reputation_url_entries = 0;
    int split_missing_refs = 0;
    int domain_missing_refs = 0;
    int qos_missing_refs = 0;
    int smart_qos_missing_refs = 0;
    int quota_missing_refs = 0;
    int conn_limit_missing_refs = 0;
    int app_policy_missing_refs = 0;
    int mmdb_valid;
    int country_prefix_available = 0;
    int country_prefix_missing = 0;
    int settings_available;
    int rc;
    int ok = 1;
    const char *state = "compiled";
    const char *error = "";

    settings_available = flowd_settings_load(&s) == 0;
    if (!settings_available) {
        ok = 0;
        state = "failed";
        error = "settings_unavailable";
        json_object_array_add(blockers, json_object_new_string("settings_unavailable"));
        json_object_array_add(warnings, json_object_new_string("flowd settings are unavailable; compile input state cannot be trusted"));
    }
    if (!body || !json_object_is_type(body, json_type_object))
        body = NULL;
    write_plan = flowd_json_bool(body, "write", 0);
    record_job = flowd_json_bool(body, "record", 1);
    if (!settings_available) {
        write_plan = 0;
        record_job = 0;
    }
    dry_run = 1;
    requested_by = flowd_json_str(body, "requested_by", "api");
    scope = flowd_json_str(body, "scope", "all");
    if (!flowd_text_ok(requested_by, 128))
        requested_by = "api";
    if (!flowd_token_ok(scope, 32))
        scope = "all";
    if (!flowd_json_bool(body, "dry_run", 1))
        json_object_array_add(warnings, json_object_new_string("compile is always dry-run; no dataplane rules were applied"));

    flowd_make_id("flow-compile", job_id, sizeof(job_id));
    snprintf(plan_leaf, sizeof(plan_leaf), "%s.json", job_id);
    if (flowd_join_path(plan_path, sizeof(plan_path), s.runtime_dir, plan_leaf) != 0)
        plan_path[0] = '\0';
    mmdb_valid = flowd_geoip_configured_mmdb_valid();
    country_prefix_index = flowd_country_prefix_index_load();
    country_prefix_available = flowd_country_prefix_index_available(country_prefix_index);
    signature_datasets = flowd_signature_datasets_load();
    content_domain_entries = flowd_plan_count_i64(
        flowd_json_int64_child_member(signature_datasets, "content", "enabled_domain_entries"));
    reputation_ip_entries = flowd_plan_count_i64(
        flowd_json_int64_child_member(signature_datasets, "reputation", "enabled_ip_entries"));
    reputation_domain_entries = flowd_plan_count_i64(
        flowd_json_int64_child_member(signature_datasets, "reputation", "enabled_domain_entries"));
    reputation_url_entries = flowd_plan_count_i64(
        flowd_json_int64_child_member(signature_datasets, "reputation", "enabled_url_entries"));
    policy_count = flowd_compile_count_load("country_policies", "SELECT COUNT(*) FROM flowd_country_policies", blockers, warnings, &ok);
    enabled_policy_count = flowd_compile_count_load("enabled_country_policies", "SELECT COUNT(*) FROM flowd_country_policies WHERE enabled=1", blockers, warnings, &ok);
    enabled_object_count = flowd_compile_count_load("enabled_objects", "SELECT COUNT(*) FROM flowd_objects WHERE enabled=1", blockers, warnings, &ok);
    enabled_route_group_count = flowd_compile_count_load("enabled_route_groups", "SELECT COUNT(*) FROM flowd_route_groups WHERE enabled=1", blockers, warnings, &ok);
    enabled_wan_capacity_count = flowd_compile_count_load("enabled_wan_capacity", "SELECT COUNT(*) FROM flowd_wan_capacity WHERE enabled=1", blockers, warnings, &ok);
    enabled_wan_health_count = flowd_compile_count_load("enabled_wan_health", "SELECT COUNT(*) FROM flowd_wan_health WHERE enabled=1", blockers, warnings, &ok);
    enabled_split_rule_count = flowd_compile_count_load("enabled_split_rules", "SELECT COUNT(*) FROM flowd_split_rules WHERE enabled=1", blockers, warnings, &ok);
    enabled_domain_rule_count = flowd_compile_count_load("enabled_domain_rules", "SELECT COUNT(*) FROM flowd_domain_rules WHERE enabled=1", blockers, warnings, &ok);
    enabled_custom_protocol_count = flowd_compile_count_load("enabled_custom_protocols", "SELECT COUNT(*) FROM flowd_custom_protocols WHERE enabled=1", blockers, warnings, &ok);
    enabled_qos_class_count = flowd_compile_count_load("enabled_qos_classes", "SELECT COUNT(*) FROM flowd_qos_classes WHERE enabled=1", blockers, warnings, &ok);
    enabled_qos_rule_count = flowd_compile_count_load("enabled_qos_rules", "SELECT COUNT(*) FROM flowd_qos_rules WHERE enabled=1", blockers, warnings, &ok);
    enabled_smart_qos_count = flowd_compile_count_load("enabled_smart_qos_categories", "SELECT COUNT(*) FROM flowd_smart_qos_categories WHERE enabled=1", blockers, warnings, &ok);
    enabled_quota_rule_count = flowd_compile_count_load("enabled_quota_rules", "SELECT COUNT(*) FROM flowd_quota_rules WHERE enabled=1", blockers, warnings, &ok);
    enabled_conn_limit_rule_count = flowd_compile_count_load("enabled_conn_limit_rules", "SELECT COUNT(*) FROM flowd_conn_limit_rules WHERE enabled=1", blockers, warnings, &ok);
    enabled_app_rule_count = flowd_compile_count_load("enabled_app_rules", "SELECT COUNT(*) FROM flowd_app_rules WHERE enabled=1", blockers, warnings, &ok);
    if (!ok && !error[0]) {
        state = "failed";
        error = "compile_inputs_unavailable";
    }

    st = flowd_config_prepare(
        "SELECT id,name,enabled,priority,direction,countries_json,action,target,family,remark,updated_at "
        "FROM flowd_country_policies WHERE enabled=1 ORDER BY priority,id");
    if (st) {
        while ((rc = sqlite3_step(st)) == SQLITE_ROW)
            flowd_policy_row_json(policies, st);
        if (rc != SQLITE_DONE) {
            ok = 0;
            if (!error[0])
                error = "country_policies_unavailable";
            state = "failed";
            json_object_array_add(blockers, json_object_new_string("country_policies_unavailable"));
            json_object_array_add(warnings, json_object_new_string("failed to read enabled country policy rows"));
        }
        sqlite3_finalize(st);
    } else {
        ok = 0;
        if (!error[0])
            error = "country_policies_unavailable";
        state = "failed";
        json_object_array_add(blockers, json_object_new_string("country_policies_unavailable"));
        json_object_array_add(warnings, json_object_new_string("failed to prepare enabled country policy query"));
    }

    json_object_object_add(country, "supported", json_object_new_boolean(1));
    json_object_object_add(country, "policy_count", json_object_new_int(policy_count));
    json_object_object_add(country, "enabled_policy_count", json_object_new_int(enabled_policy_count));
    json_object_object_add(country, "mmdb_path", json_object_new_string(FLOWD_DEFAULT_MMDB));
    json_object_object_add(country, "mmdb_valid", json_object_new_boolean(mmdb_valid));
    json_object_object_add(country, "mmdb_role", json_object_new_string("userspace_lookup"));
    json_object_object_add(country, "prefix_index", country_prefix_index);
    country_sets = flowd_country_sets_plan_from_policies(policies, country_prefix_index);
    json_object_object_add(country, "country_sets", country_sets);
    json_object_object_add(country, "policies", policies);
    country_prefix_missing = enabled_policy_count > 0 && !country_prefix_available;
    if (country_prefix_missing)
        json_object_array_add(blockers, json_object_new_string("geoip_country_prefix_missing_or_invalid"));
    if (enabled_policy_count > 0 && !mmdb_valid)
        json_object_array_add(warnings, json_object_new_string("geoip mmdb missing or invalid; country nft set planning uses geoip_country_prefix instead"));
    flowd_objects_compile_json(objects);
    flowd_custom_protocols_compile_json(custom_protocols);
    flowd_route_groups_compile_json(route_groups);
    flowd_wan_capacity_compile_json(wan_capacity);
    flowd_wan_health_compile_json(wan_health);
    split_missing_refs = flowd_split_rules_compile_json(split_rules);
    if (split_missing_refs > 0)
        json_object_array_add(blockers, json_object_new_string("split_rule_references_missing"));
    domain_missing_refs = flowd_domain_rules_compile_json(domain_rules);
    if (domain_missing_refs > 0)
        json_object_array_add(blockers, json_object_new_string("domain_rule_references_missing"));
    qos_missing_refs = flowd_qos_compile_json(qos);
    if (qos_missing_refs > 0)
        json_object_array_add(blockers, json_object_new_string("qos_references_missing"));
    smart_qos_missing_refs = flowd_smart_qos_compile_json(smart_qos);
    if (smart_qos_missing_refs > 0)
        json_object_array_add(blockers, json_object_new_string("smart_qos_references_missing"));
    quota_missing_refs = flowd_quota_rules_compile_json(quota);
    if (quota_missing_refs > 0)
        json_object_array_add(blockers, json_object_new_string("quota_references_missing"));
    conn_limit_missing_refs = flowd_conn_limit_rules_compile_json(conn_limit);
    if (conn_limit_missing_refs > 0)
        json_object_array_add(blockers, json_object_new_string("conn_limit_references_missing"));
    app_policy_missing_refs = flowd_app_rules_compile_json(app_policy);
    if (app_policy_missing_refs > 0)
        json_object_array_add(blockers, json_object_new_string("app_policy_references_missing"));

    flowd_add_table_state(legacy_tables, "flow_global");
    flowd_add_table_state(legacy_tables, "flow_qos");
    flowd_add_table_state(legacy_tables, "flow_classes");
    flowd_add_table_state(legacy_tables, "flow_groups");
    flowd_add_table_state(legacy_tables, "flow_group_members");
    flowd_add_table_state(legacy_tables, "flow_rules");
    flowd_add_table_state(legacy_tables, "flow_client_limits");
    flowd_add_table_state(legacy_tables, "flow_runtime_hits");
    flowd_add_table_state(legacy_tables, "flow_smart");
    flowd_add_table_state(legacy_tables, "flow_smart_line_mode");
    flowd_add_table_state(legacy_tables, "flow_smart_priority");
    json_object_object_add(legacy, "source", json_object_new_string("legacy jmx_flow_control tables in config.db, if present"));
    json_object_object_add(legacy, "tables", legacy_tables);

    flowd_add_plan_step(steps, "object_compile",
                        enabled_object_count > 0 ? "compile-ready" : "idle",
                        "Compile IP/MAC/port/time/domain/app/country objects into deterministic runtime sets", 0);
    flowd_add_plan_step(steps, "custom_protocols",
                        enabled_custom_protocol_count > 0 ? "compile-ready" : "idle",
                        "Compile custom L3/L4/L7 protocol definitions; DPI signature executor is still pending", 0);
    flowd_add_plan_step(steps, "country_route", enabled_policy_count > 0 ? "compile-ready" : "idle",
                        "Generate country routing match sets from GeoIP policy rows; apply executor is not enabled yet", 0);
    flowd_add_plan_step(steps, "route_group_compile",
                        enabled_route_group_count > 0 ? "compile-ready" : "idle",
                        "Compile weighted, primary/backup, PCC, and failover route groups into fwmark route-group plans", 0);
    flowd_add_plan_step(steps, "wan_capacity",
                        enabled_wan_capacity_count > 0 ? "compile-ready" : "idle",
                        "Compile WAN bandwidth calibration profiles for later tc/cake shaping; no qdisc or route state is changed by compile", 0);
    flowd_add_plan_step(steps, "wan_health",
                        enabled_wan_health_count > 0 ? "compile-ready" : "idle",
                        "Compile WAN health-check policies for later failover/PCC decisions; no active probes are executed by compile", 0);
    flowd_add_plan_step(steps, "split_route",
                        enabled_split_rule_count > 0 ? (split_missing_refs > 0 ? "blocked" : "compile-ready") : "idle",
                        "Compile five-tuple, domain, country, ISP, and app split-routing rules; apply executor is not enabled yet", 0);
    flowd_add_plan_step(steps, "domain_route",
                        enabled_domain_rule_count > 0 ? (domain_missing_refs > 0 ? "blocked" : "compile-ready") : "idle",
                        "Compile dedicated domain-route rules from domain objects into resolver/ipset route plans; resolver and dataplane executors are still pending", 0);
    flowd_add_plan_step(steps, "qos",
                        enabled_qos_rule_count > 0 ? (qos_missing_refs > 0 ? "blocked" : "compile-ready") : "idle",
                        "Compile QoS classes and rules into tc class/filter plans; apply executor is not enabled yet", 0);
    flowd_add_plan_step(steps, "smart_qos",
                        enabled_smart_qos_count > 0 ? (smart_qos_missing_refs > 0 ? "blocked" : "compile-ready") : "idle",
                        "Compile application-category priority mappings for later DPI-assisted QoS; classifier and tc executors are still pending", 0);
    flowd_add_plan_step(steps, "quota",
                        enabled_quota_rule_count > 0 ? (quota_missing_refs > 0 ? "blocked" : "compile-ready") : "idle",
                        "Compile quota/cap rules; runtime counters and reset executor are still pending", 0);
    flowd_add_plan_step(steps, "conn_limit",
                        enabled_conn_limit_rule_count > 0 ? (conn_limit_missing_refs > 0 ? "blocked" : "compile-ready") : "idle",
                        "Compile connection-limit rules; conntrack/nft executor is still pending", 0);
    flowd_add_plan_step(steps, "app_policy",
                        enabled_app_rule_count > 0 ? (app_policy_missing_refs > 0 ? "blocked" : "compile-ready") : "idle",
                        "Compile app/category accept, drop, route, qos, and mark policies; DPI/dataplane executor is still pending", 0);
    flowd_add_plan_step(steps, "content_category_feed",
                        content_domain_entries > 0 ? "compile-ready" : "idle",
                        "Plan content-category domain feeds from signature DB; resolver/dataplane executor is not enabled yet", 0);
    flowd_add_plan_step(steps, "reputation_feed",
                        (reputation_ip_entries + reputation_domain_entries + reputation_url_entries) > 0 ? "compile-ready" : "idle",
                        "Plan IP/domain/URL reputation feeds from signature DB for later policy, logd, and identityd consumption", 0);
    flowd_add_plan_step(steps, "telemetry", "missing-collector",
                        "Per-WAN category counters, active apps, DPI cache, and rule-hit counters are still pending", 0);
    json_object_array_add(blockers, json_object_new_string("dataplane_apply_executor_missing"));
    flowd_build_dataplane_artifacts(dataplane_artifacts,
                                    enabled_object_count,
                                    enabled_custom_protocol_count,
                                    enabled_route_group_count,
                                    enabled_wan_capacity_count,
                                    enabled_wan_health_count,
                                    enabled_policy_count,
                                    country_prefix_missing,
                                    enabled_split_rule_count,
                                    split_missing_refs,
                                    enabled_domain_rule_count,
                                    domain_missing_refs,
                                    enabled_qos_class_count,
                                    enabled_qos_rule_count,
                                    qos_missing_refs,
                                    enabled_smart_qos_count,
                                    smart_qos_missing_refs,
                                    enabled_quota_rule_count,
                                    quota_missing_refs,
                                    enabled_conn_limit_rule_count,
                                    conn_limit_missing_refs,
                                    enabled_app_rule_count,
                                    app_policy_missing_refs,
                                    content_domain_entries,
                                    reputation_ip_entries,
                                    reputation_domain_entries,
                                    reputation_url_entries);

    json_object_object_add(inputs, "settings_enabled", json_object_new_boolean(s.enabled));
    json_object_object_add(inputs, "settings_available", json_object_new_boolean(settings_available));
    json_object_object_add(inputs, "apply_mode", json_object_new_string(s.apply_mode));
    json_object_object_add(inputs, "runtime_dir", json_object_new_string(s.runtime_dir));
    json_object_object_add(inputs, "flow_db_path", json_object_new_string(FLOWD_DEFAULT_FLOW_DB_PATH));
    json_object_object_add(inputs, "signature_datasets", signature_datasets);
    json_object_object_add(inputs, "objects", objects);
    json_object_object_add(inputs, "custom_protocols", custom_protocols);
    json_object_object_add(inputs, "route_groups", route_groups);
    json_object_object_add(inputs, "wan_capacity", wan_capacity);
    json_object_object_add(inputs, "wan_health", wan_health);
    json_object_object_add(inputs, "split_rules", split_rules);
    json_object_object_add(inputs, "domain_rules", domain_rules);
    json_object_object_add(inputs, "qos", qos);
    json_object_object_add(inputs, "smart_qos", smart_qos);
    json_object_object_add(inputs, "quota", quota);
    json_object_object_add(inputs, "conn_limit", conn_limit);
    json_object_object_add(inputs, "app_policy", app_policy);
    json_object_object_add(inputs, "legacy_flow", legacy);
    json_object_object_add(inputs, "country_routing", country);

    json_object_object_add(plan, "version", json_object_new_int(FLOWD_SCHEMA_VERSION));
    json_object_object_add(plan, "kind", json_object_new_string("flowd-compile"));
    json_object_object_add(plan, "job_id", json_object_new_string(job_id));
    json_object_object_add(plan, "generated_at", json_object_new_int64(flowd_now_s()));
    json_object_object_add(plan, "scope", json_object_new_string(scope));
    json_object_object_add(plan, "dry_run", json_object_new_boolean(dry_run));
    json_object_object_add(plan, "applies_dataplane", json_object_new_boolean(0));
    json_object_object_add(plan, "note", json_object_new_string("compile-only plan; no nft, tc, ip rule, ip route, dns, or service reload was applied"));
    json_object_object_add(plan, "dataplane_artifacts", dataplane_artifacts);
    json_object_object_add(plan, "inputs", inputs);
    json_object_object_add(plan, "steps", steps);
    json_object_object_add(plan, "blockers", blockers);
    json_object_object_add(plan, "warnings", warnings);

    if (write_plan) {
        if (flowd_mkdir_p(s.runtime_dir, 0755) == 0 &&
            flowd_write_json_atomic(plan_path, plan) == 0) {
            written = 1;
        } else {
            ok = 0;
            state = "failed";
            error = "write_failed";
        }
    }
    if (record_job)
        saved = flowd_apply_job_save(job_id, "compile", requested_by, dry_run,
                                     write_plan ? plan_path : "", plan,
                                     state, error) == 0;
    if (record_job && !saved) {
        ok = 0;
        state = "failed";
        if (!error[0])
            error = "job_save_failed";
    }

    json_object_object_add(resp, "ok", json_object_new_boolean(ok));
    json_object_object_add(resp, "compiled", json_object_new_boolean(ok));
    json_object_object_add(resp, "state", json_object_new_string(state));
    json_object_object_add(resp, "applied", json_object_new_boolean(0));
    json_object_object_add(resp, "job_id", json_object_new_string(job_id));
    json_object_object_add(resp, "recorded", json_object_new_boolean(record_job && saved));
    json_object_object_add(resp, "written", json_object_new_boolean(written));
    json_object_object_add(resp, "plan_path", json_object_new_string(write_plan ? plan_path : ""));
    json_object_object_add(resp, "plan", plan);
    if (error[0])
        json_object_object_add(resp, "error", json_object_new_string(error));
    return resp;
}
