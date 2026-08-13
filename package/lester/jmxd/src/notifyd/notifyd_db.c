// SPDX-License-Identifier: GPL-2.0-or-later
#include "notifyd_internal.h"

#define WORKER_STATUS_VERSION "1.0"

static int notifyd_email_address_ok(const char *email);

static int notifyd_exec(sqlite3 *db, const char *sql)
{
    char *err = NULL;
    int rc;

    if (!db || !sql)
        return -1;
    rc = sqlite3_exec(db, sql, NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[dreamingwrt-notifyd] sqlite exec failed: %s sql=%s\n",
                err ? err : sqlite3_errmsg(db), sql);
        sqlite3_free(err);
        return -1;
    }
    return 0;
}

sqlite3_stmt *notifyd_prepare(const char *sql)
{
    sqlite3_stmt *st = NULL;

    if (!g_notify_db || !sql)
        return NULL;
    if (sqlite3_prepare_v2(g_notify_db, sql, -1, &st, NULL) != SQLITE_OK) {
        fprintf(stderr, "[dreamingwrt-notifyd] sqlite prepare failed: %s sql=%s\n",
                sqlite3_errmsg(g_notify_db), sql);
        return NULL;
    }
    return st;
}

sqlite3_stmt *notifyd_config_prepare(const char *sql)
{
    sqlite3_stmt *st = NULL;

    if (!g_notify_config_db || !sql)
        return NULL;
    if (sqlite3_prepare_v2(g_notify_config_db, sql, -1, &st, NULL) != SQLITE_OK) {
        fprintf(stderr, "[dreamingwrt-notifyd] config sqlite prepare failed: %s sql=%s\n",
                sqlite3_errmsg(g_notify_config_db), sql);
        return NULL;
    }
    return st;
}

static int notifyd_table_has_column(sqlite3 *db, const char *table, const char *column)
{
    sqlite3_stmt *st = NULL;
    char sql[160];
    int found = 0;

    if (!db || !table || !column)
        return 0;
    snprintf(sql, sizeof(sql), "PRAGMA table_info(%s)", table);
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return 0;
    while (sqlite3_step(st) == SQLITE_ROW) {
        const char *name = (const char *)sqlite3_column_text(st, 1);
        if (name && !strcmp(name, column)) {
            found = 1;
            break;
        }
    }
    sqlite3_finalize(st);
    return found;
}

static void notifyd_response_set_ok(struct json_object *resp, int ok)
{
    if (!resp)
        return;
    json_object_object_del(resp, "ok");
    json_object_object_add(resp, "ok", json_object_new_boolean(ok));
}

static void notifyd_response_set_first_error(struct json_object *resp, const char *error)
{
    struct json_object *existing = NULL;

    if (!resp || !error || !error[0])
        return;
    if (json_object_object_get_ex(resp, "error", &existing) && existing)
        return;
    json_object_object_add(resp, "error", json_object_new_string(error));
}

struct notifyd_event_definition {
    const char *id;
    const char *category;
    const char *label;
    const char *producer;
    const char *recovery_event;
    /*
     * Non-empty only on the half of a pair that clears the other. recovery_event
     * is symmetric (both halves point at each other), so it cannot answer "is
     * this the recovery?" -- the question min_severity handling depends on.
     * Mirrors logd_notify_event_contract.recovers_event (logd_event.c).
     */
    const char *recovers_event;
    const char *reason;
    const char *default_severity;
    int available;
};

static const struct notifyd_event_definition notifyd_event_definitions[] = {
    { "SYSTEM_RESOURCE_THRESHOLD", "SYSTEM", "System Resource Threshold", "dreamingwrt.logd.collector.resource", "", "", "", "warning", 1 },
    { "SYSTEM_LOG", "SYSTEM", "System Log", "dreamingwrt.logd", "", "", "", "notice", 1 },
    { "CALLBACKS_SUPPRESSED", "SYSTEM", "Callbacks Suppressed", "dreamingwrt.logd", "", "", "", "warning", 1 },
    { "PACKET_CAPTURE_STARTED", "SYSTEM", "Packet Capture Started", "dreamingwrt.logd", "", "", "", "notice", 1 },
    { "PACKET_CAPTURE_STOPPED", "SYSTEM", "Packet Capture Stopped", "dreamingwrt.logd", "", "", "", "notice", 1 },
    { "PACKET_CAPTURE_FINISHED", "SYSTEM", "Packet Capture Finished", "dreamingwrt.logd", "", "", "", "notice", 1 },
    { "PACKET_CAPTURE_DELETED", "SYSTEM", "Packet Capture Deleted", "dreamingwrt.logd", "", "", "", "notice", 1 },
    { "WAN_EVENT", "INTERNET_AND_WAN", "WAN Event", "dreamingwrt.logd.collector.system_log", "", "", "", "notice", 1 },
    { "PPPOE_EVENT", "INTERNET_AND_WAN", "PPPoE Event", "dreamingwrt.logd.collector.system_log", "", "", "", "notice", 1 },
    { "PORT_LINK_DOWN", "INTERNET_AND_WAN", "Port Link Down", "dreamingwrt.logd.collector.port", "PORT_LINK_UP", "", "", "warning", 1 },
    { "PORT_LINK_UP", "INTERNET_AND_WAN", "Port Link Up", "dreamingwrt.logd.collector.port", "PORT_LINK_DOWN", "PORT_LINK_DOWN", "", "notice", 1 },
    { "PORT_EVENT", "INTERNET_AND_WAN", "Port Event", "dreamingwrt.logd.collector.port", "", "", "", "notice", 1 },
    { "CLIENT_CONNECTED_WIRED", "CLIENT_DEVICES", "Wired Client Connected", "dreamingwrt.logd.collector.dhcp_lease", "CLIENT_DISCONNECTED", "", "", "notice", 1 },
    { "CLIENT_DISCONNECTED", "CLIENT_DEVICES", "Client Disconnected", "dreamingwrt.logd.collector.dhcp_lease", "CLIENT_CONNECTED_WIRED", "CLIENT_CONNECTED_WIRED", "", "notice", 1 },
    { "DHCP_EVENT", "CLIENT_DEVICES", "DHCP Event", "dreamingwrt.logd.collector.dhcp_lease", "", "", "", "notice", 1 },
    { "ADMIN_AUTH_EVENT", "ADMIN", "Admin Authentication Event", "dreamingwrt.logd.collector.system_log", "", "", "", "warning", 1 },

    { "WAN_DOWN", "INTERNET_AND_WAN", "Internet Down", "dreamingwrt-core", "WAN_RESTORED", "", "", "warning", 1 },
    { "WAN_RESTORED", "INTERNET_AND_WAN", "Internet Restored", "dreamingwrt-core", "WAN_DOWN", "WAN_DOWN", "", "notice", 1 },
    { "WAN_FAILOVER_ACTIVE", "INTERNET_AND_WAN", "WAN Failover Active", "dreamingwrt.routed.health", "WAN_FAILBACK", "", "", "warning", 1 },
    { "WAN_FAILBACK", "INTERNET_AND_WAN", "WAN Failback", "dreamingwrt.routed.health", "WAN_FAILOVER_ACTIVE", "WAN_FAILOVER_ACTIVE", "", "notice", 1 },
    { "WAN_QUALITY_DEGRADED", "INTERNET_AND_WAN", "WAN Quality Degraded", "dreamingwrt.routed.health", "WAN_QUALITY_RECOVERED", "", "", "warning", 1 },
    { "WAN_QUALITY_CRITICAL", "INTERNET_AND_WAN", "WAN Quality Critical", "dreamingwrt.routed.health", "WAN_QUALITY_RECOVERED", "", "", "critical", 1 },
    { "WAN_PENALTY_RECOVERING", "INTERNET_AND_WAN", "WAN Penalty Recovering", "dreamingwrt.routed.health", "WAN_QUALITY_RECOVERED", "", "", "notice", 1 },
    { "WAN_QUALITY_RECOVERED", "INTERNET_AND_WAN", "WAN Quality Recovered", "dreamingwrt.routed.health", "WAN_QUALITY_DEGRADED", "WAN_QUALITY_DEGRADED", "", "notice", 1 },
    { "WAN_FLAPPING", "INTERNET_AND_WAN", "WAN Flapping", "dreamingwrt-core", "", "", "", "warning", 1 },
    { "ISP_PACKET_LOSS", "INTERNET_AND_WAN", "ISP Packet Loss", "", "", "", "wan_sla_event_producer_pending", "warning", 0 },
    { "ISP_HIGH_LATENCY", "INTERNET_AND_WAN", "ISP High Latency", "", "", "", "wan_sla_event_producer_pending", "warning", 0 },
    { "DEVICE_OFFLINE", "DEVICES", "Infrastructure Device Offline", "", "DEVICE_RESTORED", "", "topology_history_not_connected_to_logd_notifyd", "warning", 0 },
    { "DEVICE_RESTORED", "DEVICES", "Infrastructure Device Restored", "", "DEVICE_OFFLINE", "DEVICE_OFFLINE", "topology_history_not_connected_to_logd_notifyd", "notice", 0 },
    { "PORT_TX_RX_ERRORS", "INTERNET_AND_WAN", "Port TX/RX Errors", "", "", "", "port_counter_delta_producer_pending", "warning", 0 },
    { "PORT_DROPPED_TRAFFIC", "INTERNET_AND_WAN", "Port Dropped Traffic", "", "", "", "port_counter_delta_producer_pending", "warning", 0 },
    { "DHCP_POOL_EXHAUSTED", "CLIENT_DEVICES", "DHCP Pool Exhausted", "dreamingwrt-core", "", "", "", "critical", 1 },
    { "CLIENT_IP_CONFLICT", "CLIENT_DEVICES", "Client IP Conflict", "", "", "", "ip_conflict_producer_pending", "warning", 0 },
    { "VPN_SITE_TO_SITE_DISCONNECTED", "VPN", "Site-to-Site VPN Disconnected", "", "VPN_SITE_TO_SITE_RESTORED", "", "vpn_state_producer_pending", "warning", 0 },
    { "VPN_SITE_TO_SITE_RESTORED", "VPN", "Site-to-Site VPN Restored", "", "VPN_SITE_TO_SITE_DISCONNECTED", "VPN_SITE_TO_SITE_DISCONNECTED", "vpn_state_producer_pending", "notice", 0 },
    { "SECURITY_DETECTION", "SECURITY", "Security Detection", "", "", "", "aegis_suricata_event_bridge_pending", "warning", 0 },
    { "CONFIG_COMMIT_FAILED", "ADMIN", "Configuration Commit Failed", "", "", "", "config_transaction_event_producer_pending", "error", 0 },
    { "APPLICATION_UPDATE_FAILED", "SYSTEM", "Application Update Failed", "", "", "", "otad_failure_event_producer_pending", "error", 0 },
    { "IMPROPER_SHUTDOWN", "SYSTEM", "Improper Shutdown", "", "", "", "boot_marker_event_producer_pending", "warning", 0 },

    /*
     * dreamingproxy is an out-of-tree Go plugin that enqueues with category
     * "PROXY". Delivery never consulted this table, so these events were being
     * routed all along, but the catalog omission hid them from the notification
     * routing UI: a user could not build a PROXY-scoped route, and info-severity
     * events were dropped because the only live route is min_severity=warning.
     * Severities below mirror the producer exactly (internal/service/
     * notifications.go and egress_drift.go); recovery events are info because
     * notify/manager.go hardcodes "info" when it resolves an active state.
     */
    { "PROXY_NODE_MASS_FAILURE", "PROXY", "Proxy Nodes Mass Failure", "dreamingproxy", "PROXY_NODE_MASS_RECOVERED", "", "", "warning", 1 },
    { "PROXY_NODE_MASS_RECOVERED", "PROXY", "Proxy Nodes Recovered", "dreamingproxy", "PROXY_NODE_MASS_FAILURE", "PROXY_NODE_MASS_FAILURE", "", "info", 1 },
    { "PROXY_CAPABILITY_EMPTY", "PROXY", "Policy Group Candidates Empty", "dreamingproxy", "PROXY_CAPABILITY_RECOVERED", "", "", "error", 1 },
    { "PROXY_CAPABILITY_RECOVERED", "PROXY", "Policy Group Candidates Recovered", "dreamingproxy", "PROXY_CAPABILITY_EMPTY", "PROXY_CAPABILITY_EMPTY", "", "info", 1 },
    { "PROXY_BINDING_OFFLINE", "PROXY", "Client Binding Offline", "dreamingproxy", "PROXY_BINDING_RESTORED", "", "", "critical", 1 },
    { "PROXY_BINDING_RESTORED", "PROXY", "Client Binding Restored", "dreamingproxy", "PROXY_BINDING_OFFLINE", "PROXY_BINDING_OFFLINE", "", "info", 1 },
    { "PROXY_ALL_WANS_DEGRADED", "PROXY", "All WAN Paths Degraded", "dreamingproxy", "PROXY_WAN_PATH_RECOVERED", "", "", "error", 1 },
    { "PROXY_WAN_PATH_RECOVERED", "PROXY", "WAN Path Recovered", "dreamingproxy", "PROXY_ALL_WANS_DEGRADED", "PROXY_ALL_WANS_DEGRADED", "", "info", 1 },
    { "PROXY_WAN_PATH_FLAPPING", "PROXY", "WAN Path Flapping", "dreamingproxy", "", "", "", "warning", 1 },
    { "PROXY_CONFIG_APPLY_FAILED", "PROXY", "Proxy Config Apply Failed", "dreamingproxy", "", "", "", "error", 1 },
    { "PROXY_CONFIG_ROLLED_BACK", "PROXY", "Proxy Config Rolled Back", "dreamingproxy", "", "", "", "warning", 1 },
    { "PROXY_SUBSCRIPTION_UPDATE_FAILED", "PROXY", "Subscription Update Failed", "dreamingproxy", "PROXY_SUBSCRIPTION_UPDATE_RECOVERED", "", "", "warning", 1 },
    { "PROXY_SUBSCRIPTION_UPDATE_RECOVERED", "PROXY", "Subscription Update Recovered", "dreamingproxy", "PROXY_SUBSCRIPTION_UPDATE_FAILED", "PROXY_SUBSCRIPTION_UPDATE_FAILED", "", "info", 1 },
    { "PROXY_RULESET_UPDATE_FAILED", "PROXY", "Ruleset Update Failed", "dreamingproxy", "PROXY_RULESET_UPDATE_RECOVERED", "", "", "warning", 1 },
    { "PROXY_RULESET_UPDATE_RECOVERED", "PROXY", "Ruleset Update Recovered", "dreamingproxy", "PROXY_RULESET_UPDATE_FAILED", "PROXY_RULESET_UPDATE_FAILED", "", "info", 1 },
    { "PROXY_CORE_UNAVAILABLE", "PROXY", "Proxy Core Unavailable", "dreamingproxy", "PROXY_CORE_RECOVERED", "", "", "error", 1 },
    { "PROXY_CORE_RECOVERED", "PROXY", "Proxy Core Recovered", "dreamingproxy", "PROXY_CORE_UNAVAILABLE", "PROXY_CORE_UNAVAILABLE", "", "info", 1 },
    /*
     * No recovery event by design: egress drift is a completed discrete change,
     * so "recovered" would wrongly claim the previous exit came back. Severity
     * is warning for operator_changed and info for unknown attribution, so the
     * default here is the more common warning form.
     */
    { "PROXY_EGRESS_DRIFT", "PROXY", "Proxy Egress Address Drift", "dreamingproxy", "", "", "", "warning", 1 },
};

static void notifyd_event_ids_json(struct json_object *cap)
{
    struct json_object *available = json_object_new_array();
    struct json_object *pending = json_object_new_array();
    size_t i;

    for (i = 0; i < sizeof(notifyd_event_definitions) / sizeof(notifyd_event_definitions[0]); i++) {
        const struct notifyd_event_definition *def = &notifyd_event_definitions[i];
        json_object_array_add(def->available ? available : pending,
                              json_object_new_string(def->id));
    }
    json_object_object_add(cap, "event_ids", available);
    json_object_object_add(cap, "pending_event_ids", pending);
}

/*
 * Enqueue used to accept any "event" string, so a typo in a producer's event
 * constant produced ok:true, exit code 0, and a delivered notification carrying
 * an id nothing downstream recognises. The producer only ever sees the exit
 * code, so nothing along the chain could report the mistake.
 *
 * Lookup covers pending definitions too: an event whose producer is not wired
 * up yet is still a real catalog id, and rejecting it would turn "not collected
 * yet" into "rejected", which is a different and more confusing failure.
 */
static const struct notifyd_event_definition *notifyd_event_definition_find(const char *id)
{
    size_t i;

    if (!id || !id[0])
        return NULL;
    for (i = 0; i < sizeof(notifyd_event_definitions) / sizeof(notifyd_event_definitions[0]); i++) {
        if (!strcmp(notifyd_event_definitions[i].id, id))
            return &notifyd_event_definitions[i];
    }
    return NULL;
}

struct json_object *notifyd_event_catalog_json(void)
{
    static const struct { const char *id; const char *label; } categories[] = {
        { "SYSTEM", "System" },
        { "INTERNET_AND_WAN", "Internet and WAN" },
        { "CLIENT_DEVICES", "Client Devices" },
        { "DEVICES", "Infrastructure Devices" },
        { "ADMIN", "Admin" },
        { "SECURITY", "Security" },
        { "VPN", "VPN" },
        /* Owned by the out-of-tree dreamingproxy plugin, not by notifyd. */
        { "PROXY", "Proxy" },
    };
    struct json_object *resp = json_object_new_object();
    struct json_object *category_array = json_object_new_array();
    struct json_object *event_array = json_object_new_array();
    size_t i;

    for (i = 0; i < sizeof(categories) / sizeof(categories[0]); i++) {
        struct json_object *category = json_object_new_object();
        json_object_object_add(category, "id", json_object_new_string(categories[i].id));
        json_object_object_add(category, "label", json_object_new_string(categories[i].label));
        json_object_array_add(category_array, category);
    }
    for (i = 0; i < sizeof(notifyd_event_definitions) / sizeof(notifyd_event_definitions[0]); i++) {
        const struct notifyd_event_definition *def = &notifyd_event_definitions[i];
        struct json_object *event = json_object_new_object();

        json_object_object_add(event, "id", json_object_new_string(def->id));
        json_object_object_add(event, "category", json_object_new_string(def->category));
        json_object_object_add(event, "label", json_object_new_string(def->label));
        json_object_object_add(event, "available", json_object_new_boolean(def->available));
        json_object_object_add(event, "producer", json_object_new_string(def->producer));
        json_object_object_add(event, "recovery_event", json_object_new_string(def->recovery_event));
        json_object_object_add(event, "recovers_event", json_object_new_string(def->recovers_event));
        json_object_object_add(event, "severity_exempt", json_object_new_boolean(def->recovers_event[0] != 0));
        json_object_object_add(event, "default_severity", json_object_new_string(def->default_severity));
        if (def->reason[0])
            json_object_object_add(event, "reason", json_object_new_string(def->reason));
        json_object_array_add(event_array, event);
    }
    json_object_object_add(resp, "ok", json_object_new_boolean(1));
    json_object_object_add(resp, "categories", category_array);
    json_object_object_add(resp, "events", event_array);
    json_object_object_add(resp, "source", json_object_new_string("dreamingwrt.notifyd.event_catalog"));
    json_object_object_add(resp, "generated_at", json_object_new_int64(notifyd_now_s()));
    return resp;
}

int notifyd_db_init(void)
{
    mkdir("/etc/dreamingwrt", 0755);
    if (sqlite3_open(NOTIFYD_DB_PATH, &g_notify_db) != SQLITE_OK) {
        fprintf(stderr, "[dreamingwrt-notifyd] open %s failed\n", NOTIFYD_DB_PATH);
        notifyd_db_close();
        return -1;
    }
    sqlite3_busy_timeout(g_notify_db, 3000);
    if (sqlite3_open(NOTIFYD_CONFIG_DB_PATH, &g_notify_config_db) != SQLITE_OK) {
        fprintf(stderr, "[dreamingwrt-notifyd] open %s failed\n", NOTIFYD_CONFIG_DB_PATH);
        notifyd_db_close();
        return -1;
    }
    sqlite3_busy_timeout(g_notify_config_db, 3000);

    if (notifyd_exec(g_notify_db, "PRAGMA journal_mode=WAL") != 0 ||
        notifyd_exec(g_notify_db, "PRAGMA foreign_keys=ON") != 0 ||
        notifyd_exec(g_notify_config_db, "PRAGMA journal_mode=WAL") != 0 ||
        notifyd_exec(g_notify_config_db, "PRAGMA foreign_keys=ON") != 0)
        goto fail;

    if (notifyd_exec(g_notify_config_db,
        "CREATE TABLE IF NOT EXISTS notifyd_settings ("
        " id INTEGER PRIMARY KEY CHECK(id=1),"
        " enabled INTEGER NOT NULL DEFAULT 1,"
        " default_channel_id TEXT NOT NULL DEFAULT 'local',"
        " max_attempts INTEGER NOT NULL DEFAULT 3,"
        " retry_base_s INTEGER NOT NULL DEFAULT 60,"
        " retry_max_s INTEGER NOT NULL DEFAULT 3600,"
        " updated_at INTEGER NOT NULL DEFAULT 0)") != 0)
        goto fail;
    if (!notifyd_table_has_column(g_notify_config_db, "notifyd_settings", "smtp_host") &&
        notifyd_exec(g_notify_config_db, "ALTER TABLE notifyd_settings ADD COLUMN smtp_host TEXT NOT NULL DEFAULT ''") != 0) goto fail;
    if (!notifyd_table_has_column(g_notify_config_db, "notifyd_settings", "smtp_port") &&
        notifyd_exec(g_notify_config_db, "ALTER TABLE notifyd_settings ADD COLUMN smtp_port INTEGER NOT NULL DEFAULT 465") != 0) goto fail;
    if (!notifyd_table_has_column(g_notify_config_db, "notifyd_settings", "smtp_security") &&
        notifyd_exec(g_notify_config_db, "ALTER TABLE notifyd_settings ADD COLUMN smtp_security TEXT NOT NULL DEFAULT 'ssl'") != 0) goto fail;
    if (!notifyd_table_has_column(g_notify_config_db, "notifyd_settings", "smtp_from") &&
        notifyd_exec(g_notify_config_db, "ALTER TABLE notifyd_settings ADD COLUMN smtp_from TEXT NOT NULL DEFAULT ''") != 0) goto fail;
    if (!notifyd_table_has_column(g_notify_config_db, "notifyd_settings", "smtp_username") &&
        notifyd_exec(g_notify_config_db, "ALTER TABLE notifyd_settings ADD COLUMN smtp_username TEXT NOT NULL DEFAULT ''") != 0) goto fail;
    if (!notifyd_table_has_column(g_notify_config_db, "notifyd_settings", "smtp_password") &&
        notifyd_exec(g_notify_config_db, "ALTER TABLE notifyd_settings ADD COLUMN smtp_password TEXT NOT NULL DEFAULT ''") != 0) goto fail;
    if (notifyd_exec(g_notify_config_db,
        "INSERT OR IGNORE INTO notifyd_settings(id,enabled,default_channel_id,max_attempts,retry_base_s,retry_max_s,updated_at) "
        "VALUES(1,1,'local',3,60,3600,0)") != 0)
        goto fail;

    if (notifyd_exec(g_notify_config_db,
        "CREATE TABLE IF NOT EXISTS notifyd_channels ("
        " id TEXT PRIMARY KEY,"
        " name TEXT NOT NULL DEFAULT '',"
        " type TEXT NOT NULL DEFAULT 'noop',"
        " enabled INTEGER NOT NULL DEFAULT 1,"
        " options_json TEXT NOT NULL DEFAULT '{}',"
        " created_at INTEGER NOT NULL DEFAULT 0,"
        " updated_at INTEGER NOT NULL DEFAULT 0)") != 0)
        goto fail;
    if (notifyd_exec(g_notify_config_db,
        "INSERT OR IGNORE INTO notifyd_channels(id,name,type,enabled,options_json,created_at,updated_at) "
        "VALUES('local','Local outbox','noop',1,'{}',0,0)") != 0)
        goto fail;

    if (notifyd_exec(g_notify_config_db,
        "CREATE TABLE IF NOT EXISTS notifyd_routes ("
        " id TEXT PRIMARY KEY,"
        " name TEXT NOT NULL DEFAULT '',"
        " enabled INTEGER NOT NULL DEFAULT 1,"
        " channel_id TEXT NOT NULL DEFAULT 'local',"
        " min_severity TEXT NOT NULL DEFAULT 'warning',"
        " category TEXT NOT NULL DEFAULT '',"
        " event TEXT NOT NULL DEFAULT '',"
        " source TEXT NOT NULL DEFAULT '',"
        " options_json TEXT NOT NULL DEFAULT '{}',"
        " created_at INTEGER NOT NULL DEFAULT 0,"
        " updated_at INTEGER NOT NULL DEFAULT 0)") != 0)
        goto fail;
    if (notifyd_exec(g_notify_config_db,
        "INSERT OR IGNORE INTO notifyd_routes(id,name,enabled,channel_id,min_severity,category,event,source,options_json,created_at,updated_at) "
        "VALUES('default-warning','Default warnings',1,'local','warning','','','','{}',0,0)") != 0)
        goto fail;

    if (notifyd_exec(g_notify_db,
        "CREATE TABLE IF NOT EXISTS notify_meta ("
        " key TEXT PRIMARY KEY, value TEXT NOT NULL DEFAULT '')") != 0)
        goto fail;
    if (notifyd_exec(g_notify_db,
        "CREATE TABLE IF NOT EXISTS notify_outbox ("
        " id TEXT PRIMARY KEY,"
        " created_at INTEGER NOT NULL,"
        " updated_at INTEGER NOT NULL,"
        " next_attempt_at INTEGER NOT NULL,"
        " channel_id TEXT NOT NULL,"
        " route_id TEXT NOT NULL DEFAULT '',"
        " event_id TEXT NOT NULL DEFAULT '',"
        " severity TEXT NOT NULL DEFAULT 'info',"
        " category TEXT NOT NULL DEFAULT '',"
        " event TEXT NOT NULL DEFAULT '',"
        " source TEXT NOT NULL DEFAULT '',"
        " title TEXT NOT NULL DEFAULT '',"
        " payload_json TEXT NOT NULL DEFAULT '{}',"
        " state TEXT NOT NULL DEFAULT 'pending',"
        " attempts INTEGER NOT NULL DEFAULT 0,"
        " max_attempts INTEGER NOT NULL DEFAULT 3,"
        " first_seen INTEGER NOT NULL DEFAULT 0,"
        " last_seen INTEGER NOT NULL DEFAULT 0,"
        " count INTEGER NOT NULL DEFAULT 1,"
        " last_error TEXT NOT NULL DEFAULT '',"
        " last_http_status INTEGER NOT NULL DEFAULT 0)") != 0)
        goto fail;
    if (notifyd_exec(g_notify_db, "CREATE INDEX IF NOT EXISTS idx_notify_outbox_state_next ON notify_outbox(state,next_attempt_at)") != 0 ||
        notifyd_exec(g_notify_db, "CREATE INDEX IF NOT EXISTS idx_notify_outbox_created ON notify_outbox(created_at DESC)") != 0)
        goto fail;
    if (!notifyd_table_has_column(g_notify_db, "notify_outbox", "dedupe_key") &&
        notifyd_exec(g_notify_db, "ALTER TABLE notify_outbox ADD COLUMN dedupe_key TEXT NOT NULL DEFAULT ''") != 0)
        goto fail;
    if (!notifyd_table_has_column(g_notify_db, "notify_outbox", "first_seen") &&
        notifyd_exec(g_notify_db, "ALTER TABLE notify_outbox ADD COLUMN first_seen INTEGER NOT NULL DEFAULT 0") != 0)
        goto fail;
    if (!notifyd_table_has_column(g_notify_db, "notify_outbox", "last_seen") &&
        notifyd_exec(g_notify_db, "ALTER TABLE notify_outbox ADD COLUMN last_seen INTEGER NOT NULL DEFAULT 0") != 0)
        goto fail;
    if (!notifyd_table_has_column(g_notify_db, "notify_outbox", "count") &&
        notifyd_exec(g_notify_db, "ALTER TABLE notify_outbox ADD COLUMN count INTEGER NOT NULL DEFAULT 1") != 0)
        goto fail;
    if (notifyd_exec(g_notify_db,
        "UPDATE notify_outbox SET first_seen=created_at WHERE first_seen=0") != 0 ||
        notifyd_exec(g_notify_db,
        "UPDATE notify_outbox SET last_seen=updated_at WHERE last_seen=0") != 0 ||
        notifyd_exec(g_notify_db,
        "UPDATE notify_outbox SET count=1 WHERE count<1") != 0)
        goto fail;
    if (notifyd_exec(g_notify_db, "CREATE INDEX IF NOT EXISTS idx_notify_outbox_dedupe ON notify_outbox(channel_id,route_id,dedupe_key,state)") != 0)
        goto fail;

    if (notifyd_exec(g_notify_db,
        "CREATE TABLE IF NOT EXISTS notify_deliveries ("
        " id INTEGER PRIMARY KEY AUTOINCREMENT,"
        " outbox_id TEXT NOT NULL,"
        " channel_id TEXT NOT NULL,"
        " ts INTEGER NOT NULL,"
        " ok INTEGER NOT NULL DEFAULT 0,"
        " http_status INTEGER NOT NULL DEFAULT 0,"
        " error TEXT NOT NULL DEFAULT '')") != 0)
        goto fail;
    if (!notifyd_table_has_column(g_notify_db, "notify_deliveries", "duration_ms") &&
        notifyd_exec(g_notify_db, "ALTER TABLE notify_deliveries ADD COLUMN duration_ms INTEGER NOT NULL DEFAULT 0") != 0)
        goto fail;
    if (notifyd_exec(g_notify_db, "CREATE INDEX IF NOT EXISTS idx_notify_deliveries_outbox ON notify_deliveries(outbox_id,ts DESC)") != 0 ||
        notifyd_exec(g_notify_db, "INSERT OR IGNORE INTO notify_meta(key,value) VALUES('schema_version','1')") != 0)
        goto fail;
    return 0;

fail:
    notifyd_db_close();
    return -1;
}

void notifyd_db_close(void)
{
    if (g_notify_db) {
        sqlite3_close(g_notify_db);
        g_notify_db = NULL;
    }
    if (g_notify_config_db) {
        sqlite3_close(g_notify_config_db);
        g_notify_config_db = NULL;
    }
}

int notifyd_settings_load(struct notifyd_settings *out)
{
    sqlite3_stmt *st;

    if (!out)
        return -1;
    memset(out, 0, sizeof(*out));
    out->enabled = 1;
    snprintf(out->default_channel_id, sizeof(out->default_channel_id), "%s", "local");
    out->max_attempts = 3;
    out->retry_base_s = 60;
    out->retry_max_s = 3600;
    st = notifyd_config_prepare("SELECT enabled,default_channel_id,max_attempts,retry_base_s,retry_max_s,"
                                "smtp_host,smtp_port,smtp_security,smtp_from,smtp_username,smtp_password "
                                "FROM notifyd_settings WHERE id=1");
    if (!st)
        return -1;
    if (sqlite3_step(st) == SQLITE_ROW) {
        out->enabled = sqlite3_column_int(st, 0);
        snprintf(out->default_channel_id, sizeof(out->default_channel_id), "%s",
                 sqlite3_column_text(st, 1) ? (const char *)sqlite3_column_text(st, 1) : "local");
        out->max_attempts = sqlite3_column_int(st, 2);
        out->retry_base_s = sqlite3_column_int(st, 3);
        out->retry_max_s = sqlite3_column_int(st, 4);
        snprintf(out->smtp_host, sizeof(out->smtp_host), "%s", notifyd_sqlite_text(st, 5, ""));
        out->smtp_port = sqlite3_column_int(st, 6);
        snprintf(out->smtp_security, sizeof(out->smtp_security), "%s", notifyd_sqlite_text(st, 7, "ssl"));
        snprintf(out->smtp_from, sizeof(out->smtp_from), "%s", notifyd_sqlite_text(st, 8, ""));
        snprintf(out->smtp_username, sizeof(out->smtp_username), "%s", notifyd_sqlite_text(st, 9, ""));
        snprintf(out->smtp_password, sizeof(out->smtp_password), "%s", notifyd_sqlite_text(st, 10, ""));
    }
    sqlite3_finalize(st);
    if (out->max_attempts < 1) out->max_attempts = 1;
    if (out->max_attempts > 20) out->max_attempts = 20;
    if (out->retry_base_s < 1) out->retry_base_s = 60;
    if (out->retry_max_s < out->retry_base_s) out->retry_max_s = out->retry_base_s;
    if (out->smtp_port < 1 || out->smtp_port > 65535) out->smtp_port = 465;
    if (strcmp(out->smtp_security, "ssl") && strcmp(out->smtp_security, "starttls") && strcmp(out->smtp_security, "none"))
        snprintf(out->smtp_security, sizeof(out->smtp_security), "%s", "ssl");
    return 0;
}

struct json_object *notifyd_status_json(void)
{
    struct notifyd_settings s;
    sqlite3_stmt *st;
    struct json_object *resp = json_object_new_object();
    struct json_object *dependencies = json_object_new_object();
    struct json_object *datasets = json_object_new_object();
    struct json_object *outbox = json_object_new_object();
    char last_error[NOTIFYD_MAX_TEXT] = "";
    int pending = 0, retry = 0, failed = 0, delivered = 0, channels = 0, routes = 0;
    int schema_version = 0;
    int64_t updated_at = 0;
    int ok = 1;
    int degraded;
    int rc;
    struct jmx_storage_guard_stats storage_guard;

    memset(&storage_guard, 0, sizeof(storage_guard));
    jmx_storage_guard_get_stats(&storage_guard);
    (void)jmx_storage_guard_check("/", &storage_guard.state);

    memset(&s, 0, sizeof(s));
    s.smtp_port = 465;
    snprintf(s.smtp_security, sizeof(s.smtp_security), "%s", "ssl");
    if (notifyd_settings_load(&s) != 0) {
        ok = 0;
        notifyd_response_set_first_error(resp, "settings_load_failed");
    }
    st = notifyd_prepare("SELECT state,COUNT(*) FROM notify_outbox GROUP BY state");
    if (st) {
        while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
            const char *state = (const char *)sqlite3_column_text(st, 0);
            int n = sqlite3_column_int(st, 1);
            if (state && !strcmp(state, "pending")) pending = n;
            else if (state && !strcmp(state, "retry")) retry = n;
            else if (state && !strcmp(state, "failed")) failed = n;
            else if (state && !strcmp(state, "delivered")) delivered = n;
        }
        if (rc != SQLITE_DONE) {
            ok = 0;
            notifyd_response_set_first_error(resp, "outbox_summary_query_failed");
        }
        sqlite3_finalize(st);
    } else {
        ok = 0;
        notifyd_response_set_first_error(resp, "outbox_summary_query_failed");
    }
    st = notifyd_config_prepare("SELECT COUNT(*) FROM notifyd_channels WHERE enabled=1");
    if (st) {
        rc = sqlite3_step(st);
        if (rc == SQLITE_ROW) channels = sqlite3_column_int(st, 0);
        else if (rc != SQLITE_DONE) {
            ok = 0;
            notifyd_response_set_first_error(resp, "channels_count_query_failed");
        }
        sqlite3_finalize(st);
    } else {
        ok = 0;
        notifyd_response_set_first_error(resp, "channels_count_query_failed");
    }
    st = notifyd_config_prepare("SELECT COUNT(*) FROM notifyd_routes WHERE enabled=1");
    if (st) {
        rc = sqlite3_step(st);
        if (rc == SQLITE_ROW) routes = sqlite3_column_int(st, 0);
        else if (rc != SQLITE_DONE) {
            ok = 0;
            notifyd_response_set_first_error(resp, "routes_count_query_failed");
        }
        sqlite3_finalize(st);
    } else {
        ok = 0;
        notifyd_response_set_first_error(resp, "routes_count_query_failed");
    }
    st = notifyd_prepare("SELECT CAST(value AS INTEGER) FROM notify_meta WHERE key='schema_version'");
    if (st) {
        rc = sqlite3_step(st);
        if (rc == SQLITE_ROW)
            schema_version = sqlite3_column_int(st, 0);
        else {
            ok = 0;
            notifyd_response_set_first_error(resp, "schema_version_unavailable");
        }
        sqlite3_finalize(st);
    } else {
        ok = 0;
        notifyd_response_set_first_error(resp, "schema_version_unavailable");
    }
    st = notifyd_prepare(
        "SELECT last_error,updated_at FROM notify_outbox WHERE last_error<>'' "
        "ORDER BY updated_at DESC LIMIT 1");
    if (st) {
        rc = sqlite3_step(st);
        if (rc == SQLITE_ROW) {
            snprintf(last_error, sizeof(last_error), "%s", notifyd_sqlite_text(st, 0, ""));
            updated_at = sqlite3_column_int64(st, 1);
        } else if (rc != SQLITE_DONE) {
            ok = 0;
            notifyd_response_set_first_error(resp, "last_error_query_failed");
        }
        sqlite3_finalize(st);
    } else {
        ok = 0;
        notifyd_response_set_first_error(resp, "last_error_query_failed");
    }
    st = notifyd_prepare("SELECT COALESCE(MAX(updated_at),0) FROM notify_outbox");
    if (st) {
        rc = sqlite3_step(st);
        if (rc == SQLITE_ROW && sqlite3_column_int64(st, 0) > updated_at)
            updated_at = sqlite3_column_int64(st, 0);
        else if (rc != SQLITE_ROW) {
            ok = 0;
            notifyd_response_set_first_error(resp, "updated_at_query_failed");
        }
        sqlite3_finalize(st);
    } else {
        ok = 0;
        notifyd_response_set_first_error(resp, "updated_at_query_failed");
    }
    if (!ok && !last_error[0])
        snprintf(last_error, sizeof(last_error), "%s", "status_query_failed");
    degraded = !ok || failed > 0 || last_error[0];
    json_object_object_add(resp, "ok", json_object_new_boolean(ok));
    json_object_object_add(resp, "service", json_object_new_string("dreamingwrt-notifyd"));
    json_object_object_add(resp, "version", json_object_new_string(WORKER_STATUS_VERSION));
    json_object_object_add(resp, "schema_version", json_object_new_int(schema_version));
    json_object_object_add(resp, "schema_source",
                           json_object_new_string("notify.db:notify_meta.schema_version"));
    json_object_object_add(resp, "migration_state", json_object_new_string(
        schema_version == NOTIFYD_SCHEMA_VERSION ? "current" :
        (schema_version > 0 ? "version_mismatch" : "unknown")));
    json_object_object_add(resp, "state", json_object_new_string(degraded ? "degraded" :
                           (s.enabled ? "running" : "disabled")));
    json_object_object_add(resp, "degraded", json_object_new_boolean(degraded));
    json_object_object_add(resp, "last_error", json_object_new_string(last_error));
    json_object_object_add(resp, "updated_at", json_object_new_int64(updated_at));
    json_object_object_add(resp, "enabled", json_object_new_boolean(s.enabled));
    json_object_object_add(resp, "default_channel_id", json_object_new_string(s.default_channel_id));
    json_object_object_add(resp, "active_channels", json_object_new_int(channels));
    json_object_object_add(resp, "active_routes", json_object_new_int(routes));
    json_object_object_add(resp, "pending", json_object_new_int(pending));
    json_object_object_add(resp, "retry", json_object_new_int(retry));
    json_object_object_add(resp, "failed", json_object_new_int(failed));
    json_object_object_add(resp, "delivered", json_object_new_int(delivered));
    json_object_object_add(resp, "storage_pressure",
                           json_object_new_string(jmx_storage_pressure_name(storage_guard.state.pressure)));
    json_object_object_add(resp, "storage_reason", json_object_new_string(storage_guard.state.reason));
    json_object_object_add(resp, "storage_total_bytes",
                           json_object_new_int64((int64_t)storage_guard.state.total_bytes));
    json_object_object_add(resp, "storage_available_bytes",
                           json_object_new_int64((int64_t)storage_guard.state.available_bytes));
    json_object_object_add(resp, "storage_used_pct",
                           json_object_new_int((int)storage_guard.state.used_pct));
    json_object_object_add(resp, "storage_checked_at",
                           json_object_new_int64(storage_guard.state.checked_at));
    json_object_object_add(resp, "storage_suppressed_writes",
                           json_object_new_int64((int64_t)g_notify_storage_suppressed));
    json_object_object_add(resp, "storage_last_suppressed_at",
                           json_object_new_int64(g_notify_storage_last_suppressed_at));
    json_object_object_add(dependencies, "outbox_db", json_object_new_boolean(g_notify_db != NULL));
    json_object_object_add(dependencies, "config_db", json_object_new_boolean(g_notify_config_db != NULL));
    json_object_object_add(resp, "dependencies", dependencies);
    json_object_object_add(outbox, "pending", json_object_new_int(pending));
    json_object_object_add(outbox, "retry", json_object_new_int(retry));
    json_object_object_add(outbox, "failed", json_object_new_int(failed));
    json_object_object_add(outbox, "delivered", json_object_new_int(delivered));
    json_object_object_add(datasets, "outbox", outbox);
    json_object_object_add(datasets, "active_channels", json_object_new_int(channels));
    json_object_object_add(datasets, "active_routes", json_object_new_int(routes));
    json_object_object_add(resp, "datasets", datasets);
    {
        struct json_object *cap = json_object_new_object();
        struct json_object *types = json_object_new_array();

        json_object_array_add(types, json_object_new_string("noop"));
        json_object_array_add(types, json_object_new_string("webhook"));
        json_object_array_add(types, json_object_new_string("email"));
        json_object_object_add(cap, "channel_types", types);
        json_object_object_add(cap, "delete_channel", json_object_new_boolean(1));
        json_object_object_add(cap, "delete_route", json_object_new_boolean(1));
        json_object_object_add(cap, "secret_redaction", json_object_new_boolean(1));
        json_object_object_add(cap, "smtp_secret_redaction", json_object_new_boolean(1));
        json_object_object_add(cap, "email_user_directory", json_object_new_boolean(1));
        json_object_object_add(cap, "smtp_configured", json_object_new_boolean(s.smtp_host[0] && s.smtp_from[0]));
        json_object_object_add(cap, "outbox_cursor", json_object_new_boolean(1));
        json_object_object_add(cap, "outbox_search", json_object_new_boolean(1));
        json_object_object_add(cap, "outbox_total", json_object_new_boolean(1));
        json_object_object_add(cap, "outbox_detail", json_object_new_boolean(1));
        json_object_object_add(cap, "delivery_attempts", json_object_new_boolean(1));
        json_object_object_add(cap, "delivery_duration_ms", json_object_new_boolean(1));
        json_object_object_add(cap, "test_send", json_object_new_boolean(1));
        json_object_object_add(cap, "retry", json_object_new_boolean(1));
        json_object_object_add(cap, "event_catalog", json_object_new_boolean(1));
        json_object_object_add(cap, "mobile_push", json_object_new_boolean(0));
        json_object_object_add(cap, "mobile_push_reason",
                               json_object_new_string("device_token_provider_not_configured"));
        notifyd_event_ids_json(cap);
        json_object_object_add(resp, "capabilities", cap);
    }
    json_object_object_add(resp, "ts", json_object_new_int64(notifyd_now_s()));
    memset(s.smtp_password, 0, sizeof(s.smtp_password));
    return resp;
}

struct json_object *notifyd_settings_json(void)
{
    struct notifyd_settings s;
    struct json_object *resp = json_object_new_object();
    int ok;

    memset(&s, 0, sizeof(s));
    s.smtp_port = 465;
    snprintf(s.smtp_security, sizeof(s.smtp_security), "%s", "ssl");
    ok = notifyd_settings_load(&s) == 0;
    json_object_object_add(resp, "ok", json_object_new_boolean(ok));
    if (!ok)
        json_object_object_add(resp, "error", json_object_new_string("settings_load_failed"));
    json_object_object_add(resp, "enabled", json_object_new_boolean(s.enabled));
    json_object_object_add(resp, "default_channel_id", json_object_new_string(s.default_channel_id));
    json_object_object_add(resp, "max_attempts", json_object_new_int(s.max_attempts));
    json_object_object_add(resp, "retry_base_s", json_object_new_int(s.retry_base_s));
    json_object_object_add(resp, "retry_max_s", json_object_new_int(s.retry_max_s));
    {
        struct json_object *smtp = json_object_new_object();
        json_object_object_add(smtp, "host", json_object_new_string(s.smtp_host));
        json_object_object_add(smtp, "port", json_object_new_int(s.smtp_port));
        json_object_object_add(smtp, "security", json_object_new_string(s.smtp_security));
        json_object_object_add(smtp, "from", json_object_new_string(s.smtp_from));
        json_object_object_add(smtp, "username", json_object_new_string(s.smtp_username));
        json_object_object_add(smtp, "password_present", json_object_new_boolean(s.smtp_password[0]));
        json_object_object_add(resp, "smtp", smtp);
    }
    memset(s.smtp_password, 0, sizeof(s.smtp_password));
    return resp;
}

static int notifyd_smtp_host_ok(const char *host)
{
    const unsigned char *p;

    if (!host || strlen(host) > 255)
        return 0;
    if (!host[0])
        return 1;
    for (p = (const unsigned char *)host; *p; p++) {
        if (!(isalnum(*p) || *p == '.' || *p == '-' || *p == ':' || *p == '[' || *p == ']'))
            return 0;
    }
    return 1;
}

struct json_object *notifyd_settings_update(struct json_object *body)
{
    struct notifyd_settings s;
    sqlite3_stmt *st;
    struct json_object *resp;
    const char *channel;
    char channel_copy[sizeof(s.default_channel_id)];
    int ok;
    struct json_object *smtp = NULL;
    const char *smtp_host, *smtp_security, *smtp_from, *smtp_username, *password_replace;
    int smtp_port, password_delete;

    if (notifyd_settings_load(&s) != 0) {
        resp = json_object_new_object();
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("settings_load_failed"));
        return resp;
    }
    if (!body || !json_object_is_type(body, json_type_object))
        body = NULL;
    s.enabled = notifyd_json_bool(body, "enabled", s.enabled);
    channel = notifyd_json_str(body, "default_channel_id", s.default_channel_id);
    if (channel && channel[0] && notifyd_id_ok(channel)) {
        /* channel may point into s.default_channel_id when the field is omitted. */
        snprintf(channel_copy, sizeof(channel_copy), "%s", channel);
        snprintf(s.default_channel_id, sizeof(s.default_channel_id), "%s", channel_copy);
    }
    s.max_attempts = notifyd_json_int(body, "max_attempts", s.max_attempts);
    s.retry_base_s = notifyd_json_int(body, "retry_base_s", s.retry_base_s);
    s.retry_max_s = notifyd_json_int(body, "retry_max_s", s.retry_max_s);
    if (body) json_object_object_get_ex(body, "smtp", &smtp);
    smtp_host = notifyd_json_str(smtp, "host", s.smtp_host);
    smtp_port = notifyd_json_int(smtp, "port", s.smtp_port);
    smtp_security = notifyd_json_str(smtp, "security", s.smtp_security);
    smtp_from = notifyd_json_str(smtp, "from", s.smtp_from);
    smtp_username = notifyd_json_str(smtp, "username", s.smtp_username);
    password_replace = notifyd_json_str(smtp, "password_replace", NULL);
    password_delete = notifyd_json_bool(smtp, "password_delete", 0);
    if (s.max_attempts < 1 || s.max_attempts > 20 || s.retry_base_s < 1 ||
        s.retry_base_s > 86400 || s.retry_max_s < s.retry_base_s || s.retry_max_s > 86400 ||
        smtp_port < 1 || smtp_port > 65535 ||
        (strcmp(smtp_security, "ssl") && strcmp(smtp_security, "starttls") && strcmp(smtp_security, "none")) ||
        !notifyd_smtp_host_ok(smtp_host) ||
        (smtp_from[0] && !notifyd_email_address_ok(smtp_from)) ||
        !notifyd_text_ok(smtp_username, 255) || strchr(smtp_username, '\r') || strchr(smtp_username, '\n') ||
        (smtp_username[0] && !strcmp(smtp_security, "none")) ||
        (password_replace && (!notifyd_text_ok(password_replace, 511) || strchr(password_replace, '\r') ||
                              strchr(password_replace, '\n') || !strcmp(password_replace, "__redacted__")))) {
        resp = json_object_new_object();
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("invalid_settings"));
        return resp;
    }
    st = notifyd_config_prepare(
        "UPDATE notifyd_settings SET enabled=?1,default_channel_id=?2,max_attempts=?3,retry_base_s=?4,retry_max_s=?5,updated_at=?6,"
        "smtp_host=?7,smtp_port=?8,smtp_security=?9,smtp_from=?10,smtp_username=?11,smtp_password=?12 WHERE id=1");
    ok = 0;
    if (st) {
        sqlite3_bind_int(st, 1, s.enabled);
        sqlite3_bind_text(st, 2, s.default_channel_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 3, s.max_attempts);
        sqlite3_bind_int(st, 4, s.retry_base_s);
        sqlite3_bind_int(st, 5, s.retry_max_s);
        sqlite3_bind_int64(st, 6, notifyd_now_s());
        sqlite3_bind_text(st, 7, smtp_host, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 8, smtp_port);
        sqlite3_bind_text(st, 9, smtp_security, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 10, smtp_from, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 11, smtp_username, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 12, password_delete ? "" : (password_replace ? password_replace : s.smtp_password), -1, SQLITE_TRANSIENT);
        ok = sqlite3_step(st) == SQLITE_DONE;
        sqlite3_finalize(st);
    }
    resp = notifyd_settings_json();
    notifyd_response_set_ok(resp, ok);
    json_object_object_add(resp, "saved", json_object_new_boolean(ok));
    if (!ok)
        json_object_object_add(resp, "error", json_object_new_string("save_failed"));
    return resp;
}

static struct json_object *notifyd_channel_options_public(const char *options_s)
{
    struct json_object *options = notifyd_json_parse_or_object(options_s);
    struct json_object *headers = NULL;
    struct json_object *public_headers = json_object_new_object();
    struct json_object *header_names = json_object_new_array();
    int count = 0;

    if (!options || !public_headers || !header_names)
        goto done;
    if (json_object_object_get_ex(options, "headers", &headers) && headers &&
        json_object_is_type(headers, json_type_object)) {
        json_object_object_foreach(headers, key, value) {
            (void)value;
            json_object_object_add(public_headers, key,
                                   json_object_new_string("__redacted__"));
            json_object_array_add(header_names, json_object_new_string(key));
            count++;
        }
    }
    json_object_object_del(options, "headers");
    if (count > 0) {
        json_object_object_add(options, "headers", public_headers);
        public_headers = NULL;
    }
    json_object_object_add(options, "headers_present", json_object_new_boolean(count > 0));
    json_object_object_add(options, "header_names", header_names);
    header_names = NULL;
done:
    if (public_headers) json_object_put(public_headers);
    if (header_names) json_object_put(header_names);
    return options ? options : json_object_new_object();
}

static void notifyd_channel_row_json(struct json_object *arr, sqlite3_stmt *st)
{
    const char *options_s = notifyd_sqlite_text(st, 4, "{}");
    struct json_object *o = json_object_new_object();

    json_object_object_add(o, "id", json_object_new_string(notifyd_sqlite_text(st, 0, "")));
    json_object_object_add(o, "name", json_object_new_string(notifyd_sqlite_text(st, 1, "")));
    json_object_object_add(o, "type", json_object_new_string(notifyd_sqlite_text(st, 2, "noop")));
    json_object_object_add(o, "enabled", json_object_new_boolean(sqlite3_column_int(st, 3)));
    json_object_object_add(o, "options", notifyd_channel_options_public(options_s));
    json_object_object_add(o, "updated_at", json_object_new_int64(sqlite3_column_int64(st, 5)));
    json_object_array_add(arr, o);
}

struct json_object *notifyd_channels_json(void)
{
    sqlite3_stmt *st;
    struct json_object *resp = json_object_new_object();
    struct json_object *arr = json_object_new_array();
    int ok = 1;
    int rc;

    st = notifyd_config_prepare("SELECT id,name,type,enabled,options_json,updated_at FROM notifyd_channels ORDER BY id");
    if (st) {
        while ((rc = sqlite3_step(st)) == SQLITE_ROW)
            notifyd_channel_row_json(arr, st);
        if (rc != SQLITE_DONE)
            ok = 0;
        sqlite3_finalize(st);
    } else {
        ok = 0;
    }
    json_object_object_add(resp, "ok", json_object_new_boolean(ok));
    if (!ok)
        json_object_object_add(resp, "error", json_object_new_string("channels_query_failed"));
    json_object_object_add(resp, "channels", arr);
    return resp;
}

static int notifyd_webhook_options_ok(struct json_object *options)
{
    const char *url;
    const char *method;
    int timeout_ms;
    struct json_object *headers = NULL;

    if (!options || !json_object_is_type(options, json_type_object))
        return 0;
    url = notifyd_json_str(options, "url", "");
    method = notifyd_json_str(options, "method", "POST");
    timeout_ms = notifyd_json_int(options, "timeout_ms", 10000);
    if (!notifyd_url_ok(url))
        return 0;
    if (strcmp(method, "POST") && strcmp(method, "PUT") && strcmp(method, "PATCH"))
        return 0;
    if (timeout_ms < 1000 || timeout_ms > 60000)
        return 0;
    if (json_object_object_get_ex(options, "headers", &headers) && headers) {
        if (!json_object_is_type(headers, json_type_object))
            return 0;
        json_object_object_foreach(headers, key, val) {
            const char *value;

            if (!json_object_is_type(val, json_type_string))
                return 0;
            value = json_object_get_string(val);
            if (!strcmp(value ? value : "", "__redacted__"))
                return 0;
            if (!notifyd_text_ok(key, 96) || !notifyd_text_ok(value, 512))
                return 0;
            if (!key[0] || strchr(key, '\n') || strchr(key, '\r') || strchr(key, ':'))
                return 0;
            if (value && (strchr(value, '\n') || strchr(value, '\r')))
                return 0;
        }
    }
    return 1;
}

static int notifyd_email_address_ok(const char *email)
{
    const char *at;
    const unsigned char *p;

    if (!email || !email[0] || strlen(email) > 254)
        return 0;
    at = strchr(email, '@');
    if (!at || at == email || !at[1] || !strchr(at + 1, '.'))
        return 0;
    for (p = (const unsigned char *)email; *p; p++) {
        if (*p <= 0x20 || *p == 0x7f || *p == '<' || *p == '>' || *p == ',' || *p == ';')
            return 0;
    }
    return 1;
}

static int notifyd_email_array_ok(struct json_object *options, const char *key,
                                  int usernames)
{
    struct json_object *values = NULL;
    int i;

    if (!json_object_object_get_ex(options, key, &values))
        return 1;
    if (!values || !json_object_is_type(values, json_type_array) ||
        json_object_array_length(values) > 64)
        return 0;
    for (i = 0; i < (int)json_object_array_length(values); i++) {
        struct json_object *value = json_object_array_get_idx(values, i);
        const char *text;

        if (!value || !json_object_is_type(value, json_type_string))
            return 0;
        text = json_object_get_string(value);
        if (usernames ? !notifyd_token_ok(text, 64) : !notifyd_email_address_ok(text))
            return 0;
    }
    return 1;
}

static int notifyd_email_options_ok(struct json_object *options)
{
    const char *prefix;
    const char *reply_to;
    struct json_object *users = NULL, *recipients = NULL;
    size_t total = 0;

    if (!options || !json_object_is_type(options, json_type_object) ||
        !notifyd_email_array_ok(options, "user_ids", 1) ||
        !notifyd_email_array_ok(options, "recipients", 0))
        return 0;
    if (json_object_object_get_ex(options, "user_ids", &users) && users)
        total += json_object_array_length(users);
    if (json_object_object_get_ex(options, "recipients", &recipients) && recipients)
        total += json_object_array_length(recipients);
    if (total < 1 || total > 64)
        return 0;
    prefix = notifyd_json_str(options, "subject_prefix", "[DreamingWrt]");
    reply_to = notifyd_json_str(options, "reply_to", "");
    if (!notifyd_text_ok(prefix, 96) || strchr(prefix, '\r') || strchr(prefix, '\n'))
        return 0;
    if (reply_to[0] && !notifyd_email_address_ok(reply_to))
        return 0;
    return 1;
}

static int notifyd_config_revision_matches(const char *sql, const char *id,
                                           int64_t expected, int64_t *current)
{
    sqlite3_stmt *st;
    int64_t value = 0;

    if (current) *current = 0;
    if (expected < 0)
        return 1;
    st = notifyd_config_prepare(sql);
    if (!st)
        return 0;
    sqlite3_bind_text(st, 1, id ? id : "", -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW)
        value = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    if (current) *current = value;
    return value == expected;
}

static struct json_object *notifyd_channel_options_existing(const char *id)
{
    sqlite3_stmt *st;
    struct json_object *options = NULL;

    st = notifyd_config_prepare("SELECT options_json FROM notifyd_channels WHERE id=?1");
    if (!st)
        return json_object_new_object();
    sqlite3_bind_text(st, 1, id ? id : "", -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW)
        options = notifyd_json_parse_or_object(notifyd_sqlite_text(st, 0, "{}"));
    sqlite3_finalize(st);
    return options ? options : json_object_new_object();
}

static int notifyd_channel_options_merge_headers(const char *id,
                                                 struct json_object *body,
                                                 struct json_object *options)
{
    struct json_object *existing = NULL, *headers = NULL, *replace = NULL;
    int delete_headers = notifyd_json_bool(body, "headers_delete", 0) ||
                         notifyd_json_bool(options, "headers_delete", 0);

    if (!options || !json_object_is_type(options, json_type_object))
        return 0;
    json_object_object_del(options, "headers_present");
    json_object_object_del(options, "header_names");
    json_object_object_del(options, "headers_delete");
    json_object_object_get_ex(body, "headers_replace", &replace);
    if (replace)
        replace = json_object_get(replace);
    else if (json_object_object_get_ex(options, "headers_replace", &replace) && replace)
        replace = json_object_get(replace);
    json_object_object_del(options, "headers_replace");
    if (replace) {
        if (!json_object_is_type(replace, json_type_object)) {
            json_object_put(replace);
            return 0;
        }
        json_object_object_add(options, "headers", replace);
        return 1;
    }
    if (delete_headers) {
        json_object_object_del(options, "headers");
        return 1;
    }
    if (json_object_object_get_ex(options, "headers", &headers) && headers) {
        if (!json_object_is_type(headers, json_type_object))
            return 0;
        if (json_object_object_length(headers) > 0)
            return 1;
        json_object_object_del(options, "headers");
    }
    existing = notifyd_channel_options_existing(id);
    if (existing && json_object_object_get_ex(existing, "headers", &headers) && headers &&
        json_object_is_type(headers, json_type_object))
        json_object_object_add(options, "headers", json_object_get(headers));
    if (existing) json_object_put(existing);
    return 1;
}

struct json_object *notifyd_channels_update(struct json_object *body)
{
    const char *id = notifyd_json_str(body, "id", "");
    const char *name = notifyd_json_str(body, "name", "");
    const char *type = notifyd_json_str(body, "type", "noop");
    int enabled = notifyd_json_bool(body, "enabled", 1);
    struct json_object *options = NULL;
    const char *options_s;
    sqlite3_stmt *st;
    struct json_object *resp = json_object_new_object();
    int ok = 0;
    int64_t now = notifyd_now_s();
    int64_t expected_updated_at = notifyd_json_i64(body, "expected_updated_at", -1);
    int64_t current_updated_at = 0;

    json_object_object_get_ex(body, "options", &options);
    if (options)
        options = json_object_get(options);
    else
        options = json_object_new_object();
    if (!id[0] || !notifyd_id_ok(id) || !notifyd_token_ok(type, 31) ||
        !notifyd_text_ok(name, 127) || !notifyd_json_fits(options, NOTIFYD_MAX_JSON - 1)) {
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("invalid_channel"));
        json_object_put(options);
        return resp;
    }
    if (strcmp(type, "noop") && strcmp(type, "webhook") && strcmp(type, "email")) {
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("unsupported_channel_type"));
        json_object_put(options);
        return resp;
    }
    if (!notifyd_config_revision_matches(
            "SELECT updated_at FROM notifyd_channels WHERE id=?1", id,
            expected_updated_at, &current_updated_at)) {
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("revision_conflict"));
        json_object_object_add(resp, "current_updated_at",
                               json_object_new_int64(current_updated_at));
        json_object_put(options);
        return resp;
    }
    if (!strcmp(type, "webhook") &&
        !notifyd_channel_options_merge_headers(id, body, options)) {
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error",
                               json_object_new_string("invalid_webhook_headers_action"));
        json_object_put(options);
        return resp;
    }
    if (!strcmp(type, "webhook") && !notifyd_webhook_options_ok(options)) {
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("invalid_webhook_options"));
        json_object_put(options);
        return resp;
    }
    if (!strcmp(type, "email") && !notifyd_email_options_ok(options)) {
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("invalid_email_options"));
        json_object_put(options);
        return resp;
    }
    options_s = options ? json_object_to_json_string(options) : "{}";
    st = notifyd_config_prepare(
        "INSERT INTO notifyd_channels(id,name,type,enabled,options_json,created_at,updated_at) "
        "VALUES(?1,?2,?3,?4,?5,?6,?6) "
        "ON CONFLICT(id) DO UPDATE SET name=excluded.name,type=excluded.type,enabled=excluded.enabled,"
        "options_json=excluded.options_json,updated_at=excluded.updated_at");
    if (st) {
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, name, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 3, type, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 4, enabled);
        sqlite3_bind_text(st, 5, options_s ? options_s : "{}", -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 6, now);
        ok = sqlite3_step(st) == SQLITE_DONE;
        sqlite3_finalize(st);
    }
    json_object_object_add(resp, "ok", json_object_new_boolean(ok));
    json_object_object_add(resp, "id", json_object_new_string(id));
    if (!ok)
        json_object_object_add(resp, "error", json_object_new_string("save_failed"));
    json_object_put(options);
    return resp;
}

struct json_object *notifyd_channels_delete(struct json_object *body)
{
    const char *id = notifyd_json_str(body, "id", "");
    struct json_object *resp = json_object_new_object();
    sqlite3_stmt *st;
    int routes = 0, pending = 0, is_default = 0, ok = 0;

    if (!notifyd_id_ok(id)) {
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("invalid_channel_id"));
        return resp;
    }
    if (!strcmp(id, "local")) {
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("builtin_channel_protected"));
        return resp;
    }
    st = notifyd_config_prepare("SELECT COUNT(*) FROM notifyd_routes WHERE channel_id=?1");
    if (st) { sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT); if (sqlite3_step(st) == SQLITE_ROW) routes = sqlite3_column_int(st, 0); sqlite3_finalize(st); }
    st = notifyd_config_prepare("SELECT COUNT(*) FROM notifyd_settings WHERE id=1 AND default_channel_id=?1");
    if (st) { sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT); if (sqlite3_step(st) == SQLITE_ROW) is_default = sqlite3_column_int(st, 0); sqlite3_finalize(st); }
    st = notifyd_prepare("SELECT COUNT(*) FROM notify_outbox WHERE channel_id=?1 AND state IN ('pending','retry')");
    if (st) { sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT); if (sqlite3_step(st) == SQLITE_ROW) pending = sqlite3_column_int(st, 0); sqlite3_finalize(st); }
    if (routes || is_default || pending) {
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("channel_in_use"));
        json_object_object_add(resp, "route_references", json_object_new_int(routes));
        json_object_object_add(resp, "default_channel", json_object_new_boolean(is_default));
        json_object_object_add(resp, "pending_deliveries", json_object_new_int(pending));
        return resp;
    }
    st = notifyd_config_prepare("DELETE FROM notifyd_channels WHERE id=?1");
    if (st) {
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        ok = sqlite3_step(st) == SQLITE_DONE && sqlite3_changes(g_notify_config_db) == 1;
        sqlite3_finalize(st);
    }
    json_object_object_add(resp, "ok", json_object_new_boolean(ok));
    json_object_object_add(resp, "id", json_object_new_string(id));
    if (!ok) json_object_object_add(resp, "error", json_object_new_string("channel_not_found"));
    return resp;
}

static void notifyd_route_row_json(struct json_object *arr, sqlite3_stmt *st)
{
    const char *options_s = notifyd_sqlite_text(st, 8, "{}");
    struct json_object *o = json_object_new_object();

    json_object_object_add(o, "id", json_object_new_string(notifyd_sqlite_text(st, 0, "")));
    json_object_object_add(o, "name", json_object_new_string(notifyd_sqlite_text(st, 1, "")));
    json_object_object_add(o, "enabled", json_object_new_boolean(sqlite3_column_int(st, 2)));
    json_object_object_add(o, "channel_id", json_object_new_string(notifyd_sqlite_text(st, 3, "")));
    json_object_object_add(o, "min_severity", json_object_new_string(notifyd_sqlite_text(st, 4, "warning")));
    json_object_object_add(o, "category", json_object_new_string(notifyd_sqlite_text(st, 5, "")));
    json_object_object_add(o, "event", json_object_new_string(notifyd_sqlite_text(st, 6, "")));
    json_object_object_add(o, "source", json_object_new_string(notifyd_sqlite_text(st, 7, "")));
    json_object_object_add(o, "options", notifyd_json_parse_or_object(options_s));
    json_object_object_add(o, "updated_at", json_object_new_int64(sqlite3_column_int64(st, 9)));
    json_object_array_add(arr, o);
}

struct json_object *notifyd_routes_json(void)
{
    sqlite3_stmt *st;
    struct json_object *resp = json_object_new_object();
    struct json_object *arr = json_object_new_array();
    int ok = 1;
    int rc;

    st = notifyd_config_prepare("SELECT id,name,enabled,channel_id,min_severity,category,event,source,options_json,updated_at FROM notifyd_routes ORDER BY id");
    if (st) {
        while ((rc = sqlite3_step(st)) == SQLITE_ROW)
            notifyd_route_row_json(arr, st);
        if (rc != SQLITE_DONE)
            ok = 0;
        sqlite3_finalize(st);
    } else {
        ok = 0;
    }
    json_object_object_add(resp, "ok", json_object_new_boolean(ok));
    if (!ok)
        json_object_object_add(resp, "error", json_object_new_string("routes_query_failed"));
    json_object_object_add(resp, "routes", arr);
    return resp;
}

struct json_object *notifyd_routes_update(struct json_object *body)
{
    const char *id = notifyd_json_str(body, "id", "");
    const char *name = notifyd_json_str(body, "name", "");
    const char *channel = notifyd_json_str(body, "channel_id", "local");
    const char *min_sev = notifyd_severity(notifyd_json_str(body, "min_severity", "warning"));
    const char *category = notifyd_json_str(body, "category", "");
    const char *event = notifyd_json_str(body, "event", "");
    const char *source = notifyd_json_str(body, "source", "");
    int enabled = notifyd_json_bool(body, "enabled", 1);
    struct json_object *options = NULL;
    const char *options_s;
    sqlite3_stmt *st;
    struct json_object *resp = json_object_new_object();
    int ok = 0;
    int64_t now = notifyd_now_s();
    int64_t expected_updated_at = notifyd_json_i64(body, "expected_updated_at", -1);
    int64_t current_updated_at = 0;

    json_object_object_get_ex(body, "options", &options);
    if (!id[0] || !notifyd_id_ok(id) || !notifyd_id_ok(channel) ||
        !notifyd_text_ok(name, 127) || !notifyd_text_ok(category, 64) ||
        !notifyd_text_ok(event, 128) || !notifyd_text_ok(source, 128) ||
        !notifyd_json_fits(options, NOTIFYD_MAX_JSON - 1)) {
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("invalid_route"));
        return resp;
    }
    if (!notifyd_config_revision_matches(
            "SELECT updated_at FROM notifyd_routes WHERE id=?1", id,
            expected_updated_at, &current_updated_at)) {
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("revision_conflict"));
        json_object_object_add(resp, "current_updated_at",
                               json_object_new_int64(current_updated_at));
        return resp;
    }
    options_s = options ? json_object_to_json_string(options) : "{}";
    st = notifyd_config_prepare(
        "INSERT INTO notifyd_routes(id,name,enabled,channel_id,min_severity,category,event,source,options_json,created_at,updated_at) "
        "VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?10) "
        "ON CONFLICT(id) DO UPDATE SET name=excluded.name,enabled=excluded.enabled,channel_id=excluded.channel_id,"
        "min_severity=excluded.min_severity,category=excluded.category,event=excluded.event,source=excluded.source,"
        "options_json=excluded.options_json,updated_at=excluded.updated_at");
    if (st) {
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, name, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 3, enabled);
        sqlite3_bind_text(st, 4, channel, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 5, min_sev, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 6, category, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 7, event, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 8, source, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 9, options_s ? options_s : "{}", -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 10, now);
        ok = sqlite3_step(st) == SQLITE_DONE;
        sqlite3_finalize(st);
    }
    json_object_object_add(resp, "ok", json_object_new_boolean(ok));
    json_object_object_add(resp, "id", json_object_new_string(id));
    if (!ok)
        json_object_object_add(resp, "error", json_object_new_string("save_failed"));
    return resp;
}

struct json_object *notifyd_routes_delete(struct json_object *body)
{
    const char *id = notifyd_json_str(body, "id", "");
    struct json_object *resp = json_object_new_object();
    sqlite3_stmt *st;
    int ok = 0;

    if (!notifyd_id_ok(id)) {
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("invalid_route_id"));
        return resp;
    }
    if (!strcmp(id, "default-warning")) {
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("builtin_route_protected"));
        return resp;
    }
    st = notifyd_config_prepare("DELETE FROM notifyd_routes WHERE id=?1");
    if (st) {
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        ok = sqlite3_step(st) == SQLITE_DONE && sqlite3_changes(g_notify_config_db) == 1;
        sqlite3_finalize(st);
    }
    json_object_object_add(resp, "ok", json_object_new_boolean(ok));
    json_object_object_add(resp, "id", json_object_new_string(id));
    if (!ok) json_object_object_add(resp, "error", json_object_new_string("route_not_found"));
    return resp;
}

int notifyd_channel_get(const char *id, struct notifyd_channel *out)
{
    sqlite3_stmt *st;
    int found = 0;

    if (!id || !id[0] || !out)
        return 0;
    memset(out, 0, sizeof(*out));
    st = notifyd_config_prepare("SELECT id,name,type,enabled,options_json FROM notifyd_channels WHERE id=?1");
    if (!st)
        return 0;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW) {
        snprintf(out->id, sizeof(out->id), "%s", sqlite3_column_text(st, 0) ? (const char *)sqlite3_column_text(st, 0) : "");
        snprintf(out->name, sizeof(out->name), "%s", sqlite3_column_text(st, 1) ? (const char *)sqlite3_column_text(st, 1) : "");
        snprintf(out->type, sizeof(out->type), "%s", sqlite3_column_text(st, 2) ? (const char *)sqlite3_column_text(st, 2) : "noop");
        out->enabled = sqlite3_column_int(st, 3);
        snprintf(out->options_json, sizeof(out->options_json), "%s", sqlite3_column_text(st, 4) ? (const char *)sqlite3_column_text(st, 4) : "{}");
        found = 1;
    }
    sqlite3_finalize(st);
    return found;
}

/*
 * A recovery event is exempt from min_severity, because the pair is asymmetric
 * in severity but symmetric in usefulness: WAN_DOWN is warning and passes, its
 * clearing event WAN_RESTORED is notice and did not, so the only live route
 * (default-warning) delivered "internet is down" and never "it came back".
 * The user was left holding an alarm nothing could clear.
 *
 * Exemption is deliberately narrow. It keys off recovers_event, so it covers
 * only the half of a pair that clears a prior alarm, and it never lowers the
 * threshold for ordinary low-severity chatter (SYSTEM_LOG, DHCP_EVENT and the
 * other notice/info events stay filtered). category/event/source selectors are
 * still applied, so an operator scoping a route to one category keeps that
 * scope. The catalog reports this per event as severity_exempt.
 */
static int notifyd_event_is_recovery(const char *event_id)
{
    const struct notifyd_event_definition *def;

    if (!event_id || !event_id[0])
        return 0;
    def = notifyd_event_definition_find(event_id);
    return def && def->recovers_event[0] ? 1 : 0;
}

static int notifyd_route_matches(sqlite3_stmt *st, struct json_object *body)
{
    const char *min_sev = (const char *)sqlite3_column_text(st, 4);
    const char *category = (const char *)sqlite3_column_text(st, 5);
    const char *event = (const char *)sqlite3_column_text(st, 6);
    const char *source = (const char *)sqlite3_column_text(st, 7);
    const char *ev_sev = notifyd_severity(notifyd_json_str(body, "severity", "info"));
    const char *ev_category = notifyd_json_str(body, "category", "");
    const char *ev_event = notifyd_json_str(body, "event", "");
    const char *ev_source = notifyd_json_str(body, "source", "");

    if (notifyd_severity_rank(ev_sev) < notifyd_severity_rank(min_sev) &&
        !notifyd_event_is_recovery(ev_event))
        return 0;
    if (category && category[0] && strcmp(category, ev_category))
        return 0;
    if (event && event[0] && strcmp(event, ev_event))
        return 0;
    if (source && source[0] && strcmp(source, ev_source))
        return 0;
    return 1;
}

static const char *notifyd_dedupe_key(struct json_object *body)
{
    const char *key;

    key = notifyd_json_str(body, "dedupe_key", "");
    if (key && key[0] && notifyd_text_ok(key, 256))
        return key;
    return "";
}

static int notifyd_coalesce_outbox(const char *channel_id, const char *route_id,
                                   struct json_object *body, int max_attempts,
                                   char *out_id, size_t out_id_len)
{
    sqlite3_stmt *st;
    const char *dedupe_key = notifyd_dedupe_key(body);
    const char *payload = body ? json_object_to_json_string(body) : "{}";
    int64_t now = notifyd_now_s();
    int rc;

    if (!dedupe_key[0])
        return 0;
    st = notifyd_prepare(
        "UPDATE notify_outbox SET "
        " updated_at=?1,next_attempt_at=?1,event_id=?2,severity=?3,category=?4,event=?5,"
        " source=?6,title=?7,payload_json=?8,state='pending',attempts=0,"
        " max_attempts=?9,last_seen=?1,count=count+1,last_error='',last_http_status=0 "
        "WHERE channel_id=?10 AND route_id=?11 AND state IN ('pending','retry','failed','delivered') "
        "AND dedupe_key=?12");
    if (!st)
        return 0;
    sqlite3_bind_int64(st, 1, now);
    sqlite3_bind_text(st, 2, notifyd_json_str(body, "id", notifyd_json_str(body, "event_id", "")), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, notifyd_severity(notifyd_json_str(body, "severity", "info")), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 4, notifyd_json_str(body, "category", ""), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 5, notifyd_json_str(body, "event", ""), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 6, notifyd_json_str(body, "source", ""), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 7, notifyd_json_str(body, "title", ""), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 8, payload ? payload : "{}", -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 9, max_attempts);
    sqlite3_bind_text(st, 10, channel_id ? channel_id : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 11, route_id ? route_id : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 12, dedupe_key, -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE || sqlite3_changes(g_notify_db) <= 0)
        return 0;
    if (out_id && out_id_len > 0) {
        st = notifyd_prepare(
            "SELECT id FROM notify_outbox "
            "WHERE channel_id=?1 AND route_id=?2 AND state IN ('pending','retry','failed','delivered') "
            "AND dedupe_key=?3 "
            "ORDER BY updated_at DESC LIMIT 1");
        if (st) {
            sqlite3_bind_text(st, 1, channel_id ? channel_id : "", -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 2, route_id ? route_id : "", -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 3, dedupe_key, -1, SQLITE_TRANSIENT);
            if (sqlite3_step(st) == SQLITE_ROW)
                snprintf(out_id, out_id_len, "%s", notifyd_sqlite_text(st, 0, ""));
            sqlite3_finalize(st);
        }
    }
    return 1;
}

static int notifyd_insert_outbox(const char *channel_id, const char *route_id,
                                 struct json_object *body, int max_attempts,
                                 char *out_id, size_t out_id_len)
{
    sqlite3_stmt *st;
    char id[NOTIFYD_MAX_ID];
    const char *payload = body ? json_object_to_json_string(body) : "{}";
    int64_t now = notifyd_now_s();
    int ok = 0;
    const char *severity = notifyd_severity(notifyd_json_str(body, "severity", "info"));
    enum jmx_storage_write_priority priority = !strcmp(severity, "critical") ?
        JMX_STORAGE_WRITE_EMERGENCY : (!strcmp(severity, "warning") || !strcmp(severity, "error") ?
        JMX_STORAGE_WRITE_IMPORTANT : JMX_STORAGE_WRITE_BULK);

    if (!jmx_storage_guard_allow("/", priority, NULL)) {
        g_notify_storage_suppressed++;
        g_notify_storage_last_suppressed_at = now;
        return 0;
    }

    if (notifyd_coalesce_outbox(channel_id, route_id, body, max_attempts, out_id, out_id_len))
        return 1;
    notifyd_make_id("ntf", id, sizeof(id));
    if (out_id && out_id_len > 0)
        snprintf(out_id, out_id_len, "%s", id);
    st = notifyd_prepare(
        "INSERT INTO notify_outbox(id,created_at,updated_at,next_attempt_at,channel_id,route_id,event_id,severity,category,event,source,title,payload_json,state,attempts,max_attempts,dedupe_key,first_seen,last_seen,count) "
        "VALUES(?1,?2,?2,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,'pending',0,?12,?13,?2,?2,1)");
    if (!st)
        return 0;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, now);
    sqlite3_bind_text(st, 3, channel_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 4, route_id ? route_id : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 5, notifyd_json_str(body, "id", notifyd_json_str(body, "event_id", "")), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 6, notifyd_severity(notifyd_json_str(body, "severity", "info")), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 7, notifyd_json_str(body, "category", ""), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 8, notifyd_json_str(body, "event", ""), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 9, notifyd_json_str(body, "source", ""), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 10, notifyd_json_str(body, "title", ""), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 11, payload ? payload : "{}", -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 12, max_attempts);
    sqlite3_bind_text(st, 13, notifyd_dedupe_key(body), -1, SQLITE_TRANSIENT);
    ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    if (ok)
        notifyd_prune_if_needed();
    return ok;
}

int notifyd_prune_if_needed(void)
{
    sqlite3_stmt *st;
    int64_t now = notifyd_now_s();
    int rc;

    st = notifyd_prepare(
        "DELETE FROM notify_outbox "
        "WHERE state IN ('delivered','failed') AND updated_at<?1");
    if (!st)
        return -1;
    sqlite3_bind_int64(st, 1, now - NOTIFYD_OUTBOX_DONE_RETENTION_SEC);
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE)
        return -1;

    st = notifyd_prepare(
        "DELETE FROM notify_outbox "
        "WHERE state IN ('pending','retry') AND created_at<?1");
    if (!st)
        return -1;
    sqlite3_bind_int64(st, 1, now - NOTIFYD_OUTBOX_PENDING_RETENTION_SEC);
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE)
        return -1;

    st = notifyd_prepare(
        "DELETE FROM notify_outbox WHERE id IN ("
        " SELECT id FROM notify_outbox ORDER BY updated_at DESC LIMIT -1 OFFSET ?1)");
    if (!st)
        return -1;
    sqlite3_bind_int(st, 1, NOTIFYD_OUTBOX_MAX_ROWS);
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE)
        return -1;

    st = notifyd_prepare(
        "DELETE FROM notify_deliveries WHERE id IN ("
        " SELECT id FROM notify_deliveries ORDER BY ts DESC LIMIT -1 OFFSET ?1)");
    if (!st)
        return -1;
    sqlite3_bind_int(st, 1, NOTIFYD_DELIVERIES_MAX_ROWS);
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE)
        return -1;

    notifyd_exec(g_notify_db, "PRAGMA wal_checkpoint(PASSIVE)");
    return 0;
}

struct json_object *notifyd_enqueue_event(struct json_object *body)
{
    struct notifyd_settings s;
    sqlite3_stmt *st;
    struct json_object *resp = json_object_new_object();
    int enqueued = 0, matched = 0;
    int route_query_ok = 1;
    int rc;

    if (notifyd_settings_load(&s) != 0) {
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("settings_load_failed"));
        return resp;
    }
    if (!s.enabled) {
        json_object_object_add(resp, "ok", json_object_new_boolean(1));
        json_object_object_add(resp, "enabled", json_object_new_boolean(0));
        json_object_object_add(resp, "enqueued", json_object_new_int(0));
        return resp;
    }
    if (!body || !notifyd_json_fits(body, NOTIFYD_MAX_JSON - 1)) {
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("invalid_payload"));
        return resp;
    }
    /*
     * Validated before any route is consulted, so a bad id cannot reach the
     * outbox. The two failures are reported separately because they need
     * different fixes: a missing field is a malformed call, an unknown id is
     * usually a typo'd or stale event constant.
     */
    {
        const char *event_id = notifyd_json_str(body, "event", "");

        if (!event_id[0]) {
            json_object_object_add(resp, "ok", json_object_new_boolean(0));
            json_object_object_add(resp, "error", json_object_new_string("event_required"));
            return resp;
        }
        if (!notifyd_event_definition_find(event_id)) {
            json_object_object_add(resp, "ok", json_object_new_boolean(0));
            json_object_object_add(resp, "error", json_object_new_string("event_unknown"));
            json_object_object_add(resp, "event", json_object_new_string(event_id));
            return resp;
        }
    }
    st = notifyd_config_prepare("SELECT id,name,enabled,channel_id,min_severity,category,event,source,options_json FROM notifyd_routes WHERE enabled=1 ORDER BY id");
    if (st) {
        while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
            const char *route_id = (const char *)sqlite3_column_text(st, 0);
            const char *channel = (const char *)sqlite3_column_text(st, 3);
            if (!notifyd_route_matches(st, body))
                continue;
            matched++;
            if (channel && channel[0] && notifyd_insert_outbox(channel, route_id, body,
                                                               s.max_attempts, NULL, 0))
                enqueued++;
        }
        if (rc != SQLITE_DONE)
            route_query_ok = 0;
        sqlite3_finalize(st);
    } else {
        route_query_ok = 0;
    }
    if (!route_query_ok) {
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "matched", json_object_new_int(matched));
        json_object_object_add(resp, "enqueued", json_object_new_int(enqueued));
        json_object_object_add(resp, "error", json_object_new_string("routes_query_failed"));
        return resp;
    }
    /*
     * Same recovery exemption as notifyd_route_matches(). Without it the
     * fallback reintroduces the drop whenever no route matched at all, e.g.
     * every route disabled or scoped elsewhere.
     */
    if (!matched && s.default_channel_id[0] &&
        (notifyd_severity_rank(notifyd_json_str(body, "severity", "info")) >= notifyd_severity_rank("warning") ||
         notifyd_event_is_recovery(notifyd_json_str(body, "event", "")))) {
        matched = 1;
        if (notifyd_insert_outbox(s.default_channel_id, "default", body, s.max_attempts, NULL, 0))
            enqueued = 1;
    }
    json_object_object_add(resp, "ok", json_object_new_boolean(!matched || enqueued == matched));
    json_object_object_add(resp, "matched", json_object_new_int(matched));
    json_object_object_add(resp, "enqueued", json_object_new_int(enqueued));
    if (matched && enqueued == 0)
        json_object_object_add(resp, "error", json_object_new_string("enqueue_failed"));
    else if (matched && enqueued < matched)
        json_object_object_add(resp, "error", json_object_new_string("partial_enqueue_failed"));
    return resp;
}

struct json_object *notifyd_enqueue_direct(struct json_object *body)
{
    struct notifyd_settings s;
    struct notifyd_channel channel;
    struct json_object *resp = json_object_new_object();
    const char *channel_id = notifyd_json_str(body, "channel_id", "");
    char outbox_id[NOTIFYD_MAX_ID] = {0};
    int ok;

    if (notifyd_settings_load(&s) != 0) {
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("settings_load_failed"));
        return resp;
    }
    if (!s.enabled) {
        json_object_object_add(resp, "ok", json_object_new_boolean(1));
        json_object_object_add(resp, "enabled", json_object_new_boolean(0));
        json_object_object_add(resp, "enqueued", json_object_new_int(0));
        return resp;
    }
    if (!channel_id[0])
        channel_id = s.default_channel_id;
    if (!notifyd_id_ok(channel_id) || !notifyd_channel_get(channel_id, &channel)) {
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("channel_not_found"));
        return resp;
    }
    if (!body || !notifyd_json_fits(body, NOTIFYD_MAX_JSON - 1)) {
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("invalid_payload"));
        return resp;
    }
    ok = notifyd_insert_outbox(channel_id, notifyd_json_str(body, "route_id", "direct"),
                               body, s.max_attempts, outbox_id, sizeof(outbox_id));
    json_object_object_add(resp, "ok", json_object_new_boolean(ok));
    json_object_object_add(resp, "enqueued", json_object_new_int(ok ? 1 : 0));
    if (ok && outbox_id[0])
        json_object_object_add(resp, "id", json_object_new_string(outbox_id));
    if (!ok)
        json_object_object_add(resp, "error", json_object_new_string("enqueue_failed"));
    return resp;
}

static int notifyd_contains_ci(const char *haystack, const char *needle)
{
    size_t needle_len;

    if (!haystack || !needle || !needle[0])
        return 0;
    needle_len = strlen(needle);
    for (; *haystack; haystack++)
        if (!strncasecmp(haystack, needle, needle_len))
            return 1;
    return 0;
}

static int notifyd_event_is(const char *event, const char *wanted)
{
    return event && wanted && !strcasecmp(event, wanted);
}

static int notifyd_json_bool_override(struct json_object *obj, const char *key,
                                      int *present)
{
    struct json_object *value = NULL;

    if (present)
        *present = 0;
    if (!obj || !key || !json_object_object_get_ex(obj, key, &value) || !value)
        return 0;
    if (present)
        *present = 1;
    return json_object_get_boolean(value) ? 1 : 0;
}

static int notifyd_browser_interrupt_policy(const char *payload_s,
                                            const char *severity,
                                            const char *category,
                                            const char *event,
                                            const char **reason)
{
    struct json_object *payload = notifyd_json_parse_or_object(payload_s);
    struct json_object *detail = NULL;
    const char *metric = "";
    const char *action = "";
    const char *message = "";
    int explicit_present = 0;
    int explicit_value;
    int rank = notifyd_severity_rank(severity);
    int allow = 0;

    if (reason)
        *reason = "not_interrupt_worthy";
    explicit_value = notifyd_json_bool_override(payload, "browser_interrupt",
                                                &explicit_present);
    if (!explicit_present &&
        json_object_object_get_ex(payload, "detail_json", &detail) && detail &&
        json_object_is_type(detail, json_type_object))
        explicit_value = notifyd_json_bool_override(detail, "browser_interrupt",
                                                    &explicit_present);
    /* Producers may suppress a browser interruption, but cannot bypass the
     * central emergency allowlist by setting browser_interrupt=true. */
    if (explicit_present && !explicit_value) {
        if (reason)
            *reason = "producer_suppressed";
        json_object_put(payload);
        return 0;
    }

    if (!detail && json_object_object_get_ex(payload, "detail", &detail) &&
        (!detail || !json_object_is_type(detail, json_type_object)))
        detail = NULL;
    if (detail) {
        metric = notifyd_json_str(detail, "metric", "");
        action = notifyd_json_str(detail, "action", "");
        message = notifyd_json_str(detail, "message",
                  notifyd_json_str(detail, "line", ""));
    }
    if (!action[0])
        action = notifyd_json_str(payload, "action", "");

    if (rank >= notifyd_severity_rank("warning") &&
        (notifyd_event_is(event, "wan_down") ||
         notifyd_event_is(event, "internet_down") ||
         notifyd_event_is(event, "connectivity_lost") ||
         notifyd_event_is(event, "all_wans_down"))) {
        allow = 1;
        if (reason) *reason = "confirmed_connectivity_loss";
    } else if (rank >= notifyd_severity_rank("critical") &&
               category && !strcasecmp(category, "resource") &&
               (notifyd_event_is(event, "threshold_exceeded") ||
                notifyd_event_is(event, "temperature_critical") ||
                notifyd_event_is(event, "thermal_critical"))) {
        allow = 1;
        if (reason)
            *reason = (notifyd_contains_ci(metric, "temp") ||
                       notifyd_contains_ci(metric, "thermal")) ?
                      "critical_temperature" : "critical_resource_pressure";
    } else if (rank >= notifyd_severity_rank("warning") &&
               ((category && (!strcasecmp(category, "security") ||
                              !strcasecmp(category, "aegis"))) ||
                notifyd_event_is(event, "security_detection")) &&
               (rank >= notifyd_severity_rank("error") ||
                notifyd_contains_ci(event, "anomaly") ||
                notifyd_contains_ci(event, "attack") ||
                notifyd_contains_ci(event, "threat") ||
                notifyd_contains_ci(event, "intrusion") ||
                notifyd_contains_ci(event, "malware") ||
                notifyd_contains_ci(event, "blocked") ||
                notifyd_contains_ci(action, "block") ||
                notifyd_contains_ci(action, "drop") ||
                notifyd_contains_ci(action, "deny"))) {
        allow = 1;
        if (reason) *reason = "confirmed_security_event";
    } else if (rank >= notifyd_severity_rank("critical") &&
               (notifyd_event_is(event, "oom") ||
                notifyd_event_is(event, "out_of_memory") ||
                notifyd_event_is(event, "kernel_panic") ||
                notifyd_event_is(event, "thermal_shutdown") ||
                notifyd_contains_ci(message, "out of memory") ||
                notifyd_contains_ci(message, "oom-killer") ||
                notifyd_contains_ci(message, "kernel panic") ||
                notifyd_contains_ci(message, "thermal shutdown"))) {
        allow = 1;
        if (reason) *reason = "critical_system_failure";
    }

    if (!allow && explicit_present && explicit_value && reason)
        *reason = "producer_request_not_whitelisted";

    json_object_put(payload);
    return allow;
}

static int notifyd_outbox_row_browser_interrupt(sqlite3_stmt *st,
                                                const char **reason)
{
    return notifyd_browser_interrupt_policy(
        notifyd_sqlite_text(st, 12, "{}"),
        notifyd_sqlite_text(st, 7, "info"),
        notifyd_sqlite_text(st, 8, ""),
        notifyd_sqlite_text(st, 9, ""), reason);
}

static void notifyd_outbox_row_json(struct json_object *arr, sqlite3_stmt *st)
{
    const char *payload_s = notifyd_sqlite_text(st, 12, "{}");
    const char *interrupt_reason = "not_interrupt_worthy";
    int browser_interrupt = notifyd_outbox_row_browser_interrupt(st,
                                                                 &interrupt_reason);
    struct json_object *o = json_object_new_object();

    json_object_object_add(o, "id", json_object_new_string(notifyd_sqlite_text(st, 0, "")));
    json_object_object_add(o, "created_at", json_object_new_int64(sqlite3_column_int64(st, 1)));
    json_object_object_add(o, "updated_at", json_object_new_int64(sqlite3_column_int64(st, 2)));
    json_object_object_add(o, "next_attempt_at", json_object_new_int64(sqlite3_column_int64(st, 3)));
    json_object_object_add(o, "channel_id", json_object_new_string(notifyd_sqlite_text(st, 4, "")));
    json_object_object_add(o, "route_id", json_object_new_string(notifyd_sqlite_text(st, 5, "")));
    json_object_object_add(o, "event_id", json_object_new_string(notifyd_sqlite_text(st, 6, "")));
    json_object_object_add(o, "severity", json_object_new_string(notifyd_sqlite_text(st, 7, "info")));
    json_object_object_add(o, "category", json_object_new_string(notifyd_sqlite_text(st, 8, "")));
    json_object_object_add(o, "event", json_object_new_string(notifyd_sqlite_text(st, 9, "")));
    json_object_object_add(o, "source", json_object_new_string(notifyd_sqlite_text(st, 10, "")));
    json_object_object_add(o, "title", json_object_new_string(notifyd_sqlite_text(st, 11, "")));
    json_object_object_add(o, "payload", notifyd_json_parse_or_object(payload_s));
    json_object_object_add(o, "state", json_object_new_string(notifyd_sqlite_text(st, 13, "pending")));
    json_object_object_add(o, "attempts", json_object_new_int(sqlite3_column_int(st, 14)));
    json_object_object_add(o, "max_attempts", json_object_new_int(sqlite3_column_int(st, 15)));
    json_object_object_add(o, "last_error", json_object_new_string(notifyd_sqlite_text(st, 16, "")));
    json_object_object_add(o, "last_http_status", json_object_new_int(sqlite3_column_int(st, 17)));
    json_object_object_add(o, "first_seen", json_object_new_int64(sqlite3_column_int64(st, 18)));
    json_object_object_add(o, "last_seen", json_object_new_int64(sqlite3_column_int64(st, 19)));
    json_object_object_add(o, "count", json_object_new_int(sqlite3_column_int(st, 20)));
    json_object_object_add(o, "browser_interrupt", json_object_new_boolean(browser_interrupt));
    json_object_object_add(o, "interrupt_reason", json_object_new_string(interrupt_reason));
    json_object_array_add(arr, o);
}

struct json_object *notifyd_outbox_list(struct json_object *body)
{
    const char *state = notifyd_json_str(body, "state", "");
    const char *search = notifyd_json_str(body, "search", "");
    const char *cursor = notifyd_json_str(body, "cursor", "");
    int interrupt_only = notifyd_json_bool(body, "interrupt_only", 0);
    int64_t since = notifyd_json_i64(body, "since", 0);
    int limit = notifyd_json_int(body, "limit", NOTIFYD_DEFAULT_LIMIT);
    sqlite3_stmt *st;
    sqlite3_stmt *count_st;
    struct json_object *resp = json_object_new_object();
    struct json_object *arr = json_object_new_array();
    int ok = 1;
    int rc;
    int64_t cursor_ts = INT64_MAX;
    char cursor_id[NOTIFYD_MAX_ID] = "";
    char search_like[600] = "";
    int total = -1;
    int returned = 0;
    int has_more = 0;
    int suppressed = 0;
    int candidates = 0;
    int i;

    if (limit <= 0 || limit > NOTIFYD_MAX_LIMIT)
        limit = NOTIFYD_DEFAULT_LIMIT;
    if (state[0] && strcmp(state, "pending") && strcmp(state, "retry") &&
        strcmp(state, "failed") && strcmp(state, "delivered")) {
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("invalid_state"));
        json_object_object_add(resp, "items", arr);
        return resp;
    }
    if (!notifyd_text_ok(search, 256)) {
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("invalid_search"));
        json_object_object_add(resp, "items", arr);
        return resp;
    }
    if (since < 0) {
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("invalid_since"));
        json_object_object_add(resp, "items", arr);
        return resp;
    }
    if (cursor[0]) {
        const char *colon = strchr(cursor, ':');
        char ts_buf[32];
        char *end = NULL;
        size_t n;

        if (!colon || colon == cursor || !colon[1] || (n = (size_t)(colon - cursor)) >= sizeof(ts_buf)) {
            json_object_object_add(resp, "ok", json_object_new_boolean(0));
            json_object_object_add(resp, "error", json_object_new_string("invalid_cursor"));
            json_object_object_add(resp, "items", arr);
            return resp;
        }
        memcpy(ts_buf, cursor, n); ts_buf[n] = '\0';
        errno = 0;
        cursor_ts = strtoll(ts_buf, &end, 10);
        if (errno || !end || *end || cursor_ts < 0 || !notifyd_id_ok(colon + 1)) {
            json_object_object_add(resp, "ok", json_object_new_boolean(0));
            json_object_object_add(resp, "error", json_object_new_string("invalid_cursor"));
            json_object_object_add(resp, "items", arr);
            return resp;
        }
        snprintf(cursor_id, sizeof(cursor_id), "%s", colon + 1);
    }
    if (search[0]) {
        size_t o = 0;
        search_like[o++] = '%';
        for (i = 0; search[i] && o + 3 < sizeof(search_like); i++) {
            if (search[i] == '%' || search[i] == '_' || search[i] == '\\')
                search_like[o++] = '\\';
            search_like[o++] = search[i];
        }
        search_like[o++] = '%'; search_like[o] = '\0';
    }
    count_st = notifyd_prepare(
        "SELECT COUNT(*) FROM notify_outbox WHERE (?1='' OR state=?1) AND "
        "(?2='' OR title LIKE ?2 ESCAPE '\\' OR event LIKE ?2 ESCAPE '\\' OR "
        "category LIKE ?2 ESCAPE '\\' OR source LIKE ?2 ESCAPE '\\' OR "
        "channel_id LIKE ?2 ESCAPE '\\' OR route_id LIKE ?2 ESCAPE '\\') AND "
        "(?3=0 OR last_seen>=?3)");
    if (count_st) {
        sqlite3_bind_text(count_st, 1, state, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(count_st, 2, search_like, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(count_st, 3, since);
        if (sqlite3_step(count_st) == SQLITE_ROW) total = sqlite3_column_int(count_st, 0);
        sqlite3_finalize(count_st);
    }
    st = notifyd_prepare(
        "SELECT id,created_at,updated_at,next_attempt_at,channel_id,route_id,event_id,severity,category,event,source,title,payload_json,state,attempts,max_attempts,last_error,last_http_status,first_seen,last_seen,count "
        "FROM notify_outbox WHERE (?1='' OR state=?1) AND "
        "(?2='' OR title LIKE ?2 ESCAPE '\\' OR event LIKE ?2 ESCAPE '\\' OR category LIKE ?2 ESCAPE '\\' OR source LIKE ?2 ESCAPE '\\' OR channel_id LIKE ?2 ESCAPE '\\' OR route_id LIKE ?2 ESCAPE '\\') AND "
        "(?3=0 OR last_seen>=?3) AND "
        "(?4='' OR created_at<?5 OR (created_at=?5 AND id<?4)) "
        "ORDER BY CASE WHEN ?7=1 THEN last_seen ELSE created_at END DESC,"
        "created_at DESC,id DESC LIMIT ?6");
    if (st) {
        sqlite3_bind_text(st, 1, state, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, search_like, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 3, since);
        sqlite3_bind_text(st, 4, cursor_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 5, cursor_ts);
        sqlite3_bind_int(st, 6, interrupt_only ? NOTIFYD_MAX_LIMIT : limit + 1);
        sqlite3_bind_int(st, 7, interrupt_only);
    }
    if (st) {
        while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
            candidates++;
            if (interrupt_only && !notifyd_outbox_row_browser_interrupt(st, NULL)) {
                suppressed++;
                continue;
            }
            if (returned < limit) {
                notifyd_outbox_row_json(arr, st);
                returned++;
            } else {
                has_more = 1;
            }
        }
        if (rc != SQLITE_DONE)
            ok = 0;
        sqlite3_finalize(st);
    } else {
        ok = 0;
    }
    json_object_object_add(resp, "ok", json_object_new_boolean(ok));
    if (!ok)
        json_object_object_add(resp, "error", json_object_new_string("outbox_query_failed"));
    json_object_object_add(resp, "items", arr);
    json_object_object_add(resp, "total", json_object_new_int(
        interrupt_only ? returned + (has_more ? 1 : 0) : (total < 0 ? 0 : total)));
    json_object_object_add(resp, "limit", json_object_new_int(limit));
    json_object_object_add(resp, "has_more", json_object_new_boolean(has_more));
    json_object_object_add(resp, "cursor", json_object_new_string(cursor));
    if (has_more && returned > 0) {
        struct json_object *last = json_object_array_get_idx(arr, returned - 1);
        char next_cursor[160];
        snprintf(next_cursor, sizeof(next_cursor), "%lld:%s",
                 (long long)notifyd_json_i64(last, "created_at", 0),
                 notifyd_json_str(last, "id", ""));
        json_object_object_add(resp, "next_cursor", json_object_new_string(next_cursor));
    } else {
        json_object_object_add(resp, "next_cursor", json_object_new_string(""));
    }
    json_object_object_add(resp, "search", json_object_new_string(search));
    json_object_object_add(resp, "state", json_object_new_string(state));
    json_object_object_add(resp, "since", json_object_new_int64(since));
    json_object_object_add(resp, "interrupt_only", json_object_new_boolean(interrupt_only));
    json_object_object_add(resp, "suppressed", json_object_new_int(suppressed));
    json_object_object_add(resp, "candidate_count", json_object_new_int(candidates));
    json_object_object_add(resp, "total_exact", json_object_new_boolean(!interrupt_only));
    json_object_object_add(resp, "interrupt_policy", json_object_new_string(
        "central_allowlist_confirmed_connectivity_loss_or_critical_resource_or_confirmed_security_or_critical_system_failure"));
    return resp;
}

struct json_object *notifyd_outbox_get(struct json_object *body)
{
    const char *id = notifyd_json_str(body, "id", "");
    sqlite3_stmt *st;
    struct json_object *resp = json_object_new_object();
    struct json_object *items = json_object_new_array();
    struct json_object *attempts = json_object_new_array();

    if (!notifyd_id_ok(id)) {
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("invalid_id"));
        json_object_object_add(resp, "attempts", attempts);
        json_object_put(items);
        return resp;
    }
    st = notifyd_prepare(
        "SELECT id,created_at,updated_at,next_attempt_at,channel_id,route_id,event_id,severity,category,event,source,title,payload_json,state,attempts,max_attempts,last_error,last_http_status,first_seen,last_seen,count "
        "FROM notify_outbox WHERE id=?1");
    if (st) {
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) == SQLITE_ROW)
            notifyd_outbox_row_json(items, st);
        sqlite3_finalize(st);
    }
    if (json_object_array_length(items) == 0) {
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("outbox_not_found"));
        json_object_object_add(resp, "attempts", attempts);
        json_object_put(items);
        return resp;
    }
    st = notifyd_prepare(
        "SELECT id,ts,ok,http_status,error,duration_ms FROM notify_deliveries WHERE outbox_id=?1 ORDER BY ts DESC,id DESC");
    if (st) {
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        while (sqlite3_step(st) == SQLITE_ROW) {
            struct json_object *attempt = json_object_new_object();
            json_object_object_add(attempt, "id", json_object_new_int64(sqlite3_column_int64(st, 0)));
            json_object_object_add(attempt, "ts", json_object_new_int64(sqlite3_column_int64(st, 1)));
            json_object_object_add(attempt, "ok", json_object_new_boolean(sqlite3_column_int(st, 2)));
            json_object_object_add(attempt, "http_status", json_object_new_int(sqlite3_column_int(st, 3)));
            json_object_object_add(attempt, "error", json_object_new_string(notifyd_sqlite_text(st, 4, "")));
            json_object_object_add(attempt, "duration_ms", json_object_new_int(sqlite3_column_int(st, 5)));
            json_object_array_add(attempts, attempt);
        }
        sqlite3_finalize(st);
    }
    json_object_object_add(resp, "ok", json_object_new_boolean(1));
    json_object_object_add(resp, "item", json_object_get(json_object_array_get_idx(items, 0)));
    json_object_object_add(resp, "attempts", attempts);
    json_object_object_add(resp, "attempt_count", json_object_new_int((int)json_object_array_length(attempts)));
    json_object_object_add(resp, "source", json_object_new_string("notify.db:notify_outbox+notify_deliveries"));
    json_object_put(items);
    return resp;
}

struct json_object *notifyd_outbox_retry(struct json_object *body)
{
    const char *id = notifyd_json_str(body, "id", "");
    sqlite3_stmt *st;
    struct json_object *resp = json_object_new_object();
    int ok = 0;

    if (!notifyd_id_ok(id)) {
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("invalid_id"));
        return resp;
    }
    st = notifyd_prepare("UPDATE notify_outbox SET state='pending',next_attempt_at=?1,updated_at=?1,last_error='' WHERE id=?2");
    if (st) {
        sqlite3_bind_int64(st, 1, notifyd_now_s());
        sqlite3_bind_text(st, 2, id, -1, SQLITE_TRANSIENT);
        ok = sqlite3_step(st) == SQLITE_DONE && sqlite3_changes(g_notify_db) > 0;
        sqlite3_finalize(st);
    }
    json_object_object_add(resp, "ok", json_object_new_boolean(ok));
    json_object_object_add(resp, "id", json_object_new_string(id));
    if (!ok)
        json_object_object_add(resp, "error", json_object_new_string("not_found"));
    return resp;
}

int notifyd_delivery_record(const char *outbox_id, const char *channel_id,
                            int ok, long http_status, const char *error,
                            int duration_ms)
{
    sqlite3_stmt *st;
    int rc = 0;

    if (!jmx_storage_guard_allow("/", JMX_STORAGE_WRITE_BULK, NULL)) {
        g_notify_storage_suppressed++;
        g_notify_storage_last_suppressed_at = notifyd_now_s();
        return 0;
    }
    st = notifyd_prepare(
        "INSERT INTO notify_deliveries(outbox_id,channel_id,ts,ok,http_status,error,duration_ms) VALUES(?1,?2,?3,?4,?5,?6,?7)");
    if (!st)
        return 0;
    sqlite3_bind_text(st, 1, outbox_id ? outbox_id : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, channel_id ? channel_id : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 3, notifyd_now_s());
    sqlite3_bind_int(st, 4, ok);
    sqlite3_bind_int(st, 5, (int)http_status);
    sqlite3_bind_text(st, 6, error ? error : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 7, duration_ms < 0 ? 0 : duration_ms);
    rc = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return rc;
}

int notifyd_mark_delivery_result(const struct notifyd_outbox_item *item,
                                 int ok, long http_status, const char *error,
                                 int duration_ms)
{
    struct notifyd_settings s;
    sqlite3_stmt *st;
    int attempts;
    int64_t now = notifyd_now_s();
    int64_t next = now;
    const char *state;
    int rc = 0;

    if (!item)
        return 0;
    if (notifyd_settings_load(&s) != 0)
        return 0;
    attempts = item->attempts + 1;
    if (ok) {
        state = "delivered";
    } else if (attempts >= item->max_attempts) {
        state = "failed";
    } else {
        int delay = s.retry_base_s;
        int i;

        for (i = 1; i < attempts; i++) {
            if (delay < s.retry_max_s / 2) delay *= 2;
            else { delay = s.retry_max_s; break; }
        }
        if (delay > s.retry_max_s) delay = s.retry_max_s;
        next = now + delay;
        state = "retry";
    }
    st = notifyd_prepare(
        "UPDATE notify_outbox SET state=?1,attempts=?2,next_attempt_at=?3,updated_at=?4,last_error=?5,last_http_status=?6 WHERE id=?7");
    if (st) {
        sqlite3_bind_text(st, 1, state, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 2, attempts);
        sqlite3_bind_int64(st, 3, next);
        sqlite3_bind_int64(st, 4, now);
        sqlite3_bind_text(st, 5, error ? error : "", -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 6, (int)http_status);
        sqlite3_bind_text(st, 7, item->id, -1, SQLITE_TRANSIENT);
        rc = sqlite3_step(st) == SQLITE_DONE;
        sqlite3_finalize(st);
    }
    notifyd_delivery_record(item->id, item->channel_id, ok, http_status, error, duration_ms);
    return rc;
}
