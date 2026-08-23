// SPDX-License-Identifier: GPL-2.0-or-later
#include "otad_internal.h"

static int otad_exec(sqlite3 *db, const char *sql)
{
    char *err = NULL;
    int rc;

    if (!db || !sql)
        return -1;
    rc = sqlite3_exec(db, sql, NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[dreamingwrt-otad] sqlite exec failed: %s sql=%s\n",
                err ? err : sqlite3_errmsg(db), sql);
        sqlite3_free(err);
        return -1;
    }
    return 0;
}

static void otad_db_error(char *error, size_t error_len, const char *value)
{
    if (error && error_len)
        snprintf(error, error_len, "%s", value ? value : "operation_db_error");
}

static int otad_db_add_column(sqlite3 *db, const char *table,
                              const char *column, const char *definition)
{
    sqlite3_stmt *st = NULL;
    char sql[512];
    int found = 0;

    if (!db || !table || !column || !definition ||
        snprintf(sql, sizeof(sql), "PRAGMA table_info(%s)", table) >= (int)sizeof(sql) ||
        sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return -1;
    while (sqlite3_step(st) == SQLITE_ROW) {
        const char *name = (const char *)sqlite3_column_text(st, 1);

        if (name && !strcmp(name, column)) {
            found = 1;
            break;
        }
    }
    sqlite3_finalize(st);
    if (found)
        return 0;
    if (snprintf(sql, sizeof(sql), "ALTER TABLE %s ADD COLUMN %s %s",
                 table, column, definition) >= (int)sizeof(sql))
        return -1;
    return otad_exec(db, sql);
}

sqlite3_stmt *otad_config_prepare(const char *sql)
{
    sqlite3_stmt *st = NULL;

    if (!g_otad_config_db || !sql)
        return NULL;
    if (sqlite3_prepare_v2(g_otad_config_db, sql, -1, &st, NULL) != SQLITE_OK) {
        fprintf(stderr, "[dreamingwrt-otad] config prepare failed: %s sql=%s\n",
                sqlite3_errmsg(g_otad_config_db), sql);
        return NULL;
    }
    return st;
}

sqlite3_stmt *otad_inventory_prepare(const char *sql)
{
    sqlite3_stmt *st = NULL;

    if (!g_otad_inventory_db || !sql)
        return NULL;
    if (sqlite3_prepare_v2(g_otad_inventory_db, sql, -1, &st, NULL) != SQLITE_OK) {
        fprintf(stderr, "[dreamingwrt-otad] inventory prepare failed: %s sql=%s\n",
                sqlite3_errmsg(g_otad_inventory_db), sql);
        return NULL;
    }
    return st;
}

static int otad_db_init_fail(void)
{
    if (g_otad_config_db) {
        sqlite3_close(g_otad_config_db);
        g_otad_config_db = NULL;
    }
    if (g_otad_inventory_db) {
        sqlite3_close(g_otad_inventory_db);
        g_otad_inventory_db = NULL;
    }
    return -1;
}

int otad_db_init(void)
{
    if (g_otad_config_db && g_otad_inventory_db)
        return 0;
    if (otad_mkdir_p("/etc/dreamingwrt", 0755) != 0) {
        fprintf(stderr, "[dreamingwrt-otad] create /etc/dreamingwrt failed\n");
        return -1;
    }
    if (sqlite3_open(OTAD_CONFIG_DB_PATH, &g_otad_config_db) != SQLITE_OK) {
        fprintf(stderr, "[dreamingwrt-otad] open %s failed\n", OTAD_CONFIG_DB_PATH);
        return otad_db_init_fail();
    }
    sqlite3_busy_timeout(g_otad_config_db, 3000);
    if (sqlite3_open(OTAD_INVENTORY_DB_PATH, &g_otad_inventory_db) != SQLITE_OK) {
        fprintf(stderr, "[dreamingwrt-otad] open %s failed\n", OTAD_INVENTORY_DB_PATH);
        return otad_db_init_fail();
    }
    sqlite3_busy_timeout(g_otad_inventory_db, 3000);
    if (otad_exec(g_otad_config_db, "PRAGMA journal_mode=WAL") != 0 ||
        otad_exec(g_otad_inventory_db, "PRAGMA journal_mode=WAL") != 0)
        return otad_db_init_fail();

    if (otad_exec(g_otad_config_db,
        "CREATE TABLE IF NOT EXISTS ota_state ("
        " key TEXT PRIMARY KEY,"
        " value TEXT NOT NULL DEFAULT '',"
        " updated_at INTEGER NOT NULL DEFAULT 0)") != 0)
        return otad_db_init_fail();
    if (otad_exec(g_otad_config_db,
        "CREATE TABLE IF NOT EXISTS ota_slots ("
        " slot_name TEXT PRIMARY KEY,"
        " version TEXT NOT NULL DEFAULT '',"
        " build_id TEXT NOT NULL DEFAULT '',"
        " state TEXT NOT NULL DEFAULT 'unknown',"
        " boot_attempts INTEGER NOT NULL DEFAULT 0,"
        " last_boot_at INTEGER NOT NULL DEFAULT 0,"
        " last_good_at INTEGER NOT NULL DEFAULT 0,"
        " last_error TEXT NOT NULL DEFAULT '',"
        " rootfs_sha256 TEXT NOT NULL DEFAULT '',"
        " updated_at INTEGER NOT NULL DEFAULT 0)") != 0)
        return otad_db_init_fail();
    if (otad_exec(g_otad_config_db,
        "CREATE TABLE IF NOT EXISTS ota_jobs ("
        " id TEXT PRIMARY KEY,"
        " package_id TEXT NOT NULL DEFAULT '',"
        " package_type TEXT NOT NULL DEFAULT '',"
        " from_version TEXT NOT NULL DEFAULT '',"
        " to_version TEXT NOT NULL DEFAULT '',"
        " state TEXT NOT NULL DEFAULT 'idle',"
        " progress INTEGER NOT NULL DEFAULT 0,"
        " manifest_json TEXT NOT NULL DEFAULT '{}',"
        " error TEXT NOT NULL DEFAULT '',"
        " created_at INTEGER NOT NULL DEFAULT 0,"
        " updated_at INTEGER NOT NULL DEFAULT 0)") != 0)
        return otad_db_init_fail();
    if (otad_exec(g_otad_inventory_db,
        "CREATE TABLE IF NOT EXISTS ota_operations ("
        " operation_id TEXT PRIMARY KEY,"
        " kind TEXT NOT NULL,"
        " action TEXT NOT NULL,"
        " upload_id TEXT NOT NULL DEFAULT '',"
        " state TEXT NOT NULL DEFAULT 'validating',"
        " progress INTEGER NOT NULL DEFAULT 0,"
        " worker_pid INTEGER NOT NULL DEFAULT 0,"
        " source_size INTEGER NOT NULL DEFAULT 0,"
        " source_sha256 TEXT NOT NULL DEFAULT '',"
        " from_version TEXT NOT NULL DEFAULT '',"
        " to_version TEXT NOT NULL DEFAULT '',"
        " build_id TEXT NOT NULL DEFAULT '',"
        " target_slot TEXT NOT NULL DEFAULT '',"
        " manifest_digest TEXT NOT NULL DEFAULT '',"
        " signing_key_id TEXT NOT NULL DEFAULT '',"
        " trust_policy_version INTEGER NOT NULL DEFAULT 0,"
        " trust_policy_digest TEXT NOT NULL DEFAULT '',"
        " device_identity_digest TEXT NOT NULL DEFAULT '',"
        " topology_digest TEXT NOT NULL DEFAULT '',"
        " authenticity_verified INTEGER NOT NULL DEFAULT 0,"
        " target_compatible INTEGER NOT NULL DEFAULT 0,"
        " policy_passed INTEGER NOT NULL DEFAULT 0,"
        " options_json TEXT NOT NULL DEFAULT '{}',"
        " result_json TEXT NOT NULL DEFAULT '{}',"
        " error_code TEXT NOT NULL DEFAULT '',"
        " error_message TEXT NOT NULL DEFAULT '',"
        " created_at INTEGER NOT NULL,"
        " started_at INTEGER NOT NULL DEFAULT 0,"
        " updated_at INTEGER NOT NULL,"
        " completed_at INTEGER NOT NULL DEFAULT 0)") != 0)
        return otad_db_init_fail();
    if (otad_db_add_column(g_otad_inventory_db, "ota_operations",
                           "manifest_digest", "TEXT NOT NULL DEFAULT ''") != 0 ||
        otad_db_add_column(g_otad_inventory_db, "ota_operations",
                           "signing_key_id", "TEXT NOT NULL DEFAULT ''") != 0 ||
        otad_db_add_column(g_otad_inventory_db, "ota_operations",
                           "trust_policy_version", "INTEGER NOT NULL DEFAULT 0") != 0 ||
        otad_db_add_column(g_otad_inventory_db, "ota_operations",
                           "trust_policy_digest", "TEXT NOT NULL DEFAULT ''") != 0 ||
        otad_db_add_column(g_otad_inventory_db, "ota_operations",
                           "device_identity_digest", "TEXT NOT NULL DEFAULT ''") != 0 ||
        otad_db_add_column(g_otad_inventory_db, "ota_operations",
                           "topology_digest", "TEXT NOT NULL DEFAULT ''") != 0 ||
        otad_db_add_column(g_otad_inventory_db, "ota_operations",
                           "authenticity_verified", "INTEGER NOT NULL DEFAULT 0") != 0 ||
        otad_db_add_column(g_otad_inventory_db, "ota_operations",
                           "target_compatible", "INTEGER NOT NULL DEFAULT 0") != 0 ||
        otad_db_add_column(g_otad_inventory_db, "ota_operations",
                           "policy_passed", "INTEGER NOT NULL DEFAULT 0") != 0)
        return otad_db_init_fail();
    if (otad_exec(g_otad_inventory_db,
        "CREATE INDEX IF NOT EXISTS ota_operations_updated_idx "
        "ON ota_operations(updated_at DESC)") != 0)
        return otad_db_init_fail();
    if (otad_exec(g_otad_inventory_db,
        "DROP INDEX IF EXISTS ota_operations_one_firmware_apply") != 0)
        return otad_db_init_fail();
    if (otad_exec(g_otad_inventory_db,
        "CREATE UNIQUE INDEX IF NOT EXISTS ota_operations_one_firmware_apply "
        "ON ota_operations(kind) WHERE kind='firmware' AND action='apply' "
        "AND state IN ('writing','rebooting','reconnecting')") != 0)
        return otad_db_init_fail();
    /*
     * The same exclusion for hot updates. Two concurrent hot applies would race
     * each other's atomic replacements over the same targets, so only one may be
     * in 'writing' at a time. Keyed on kind, which the partial index makes a
     * single-row constraint per kind rather than a global one - a hot apply and a
     * firmware apply are still refused independently of each other.
     */
    if (otad_exec(g_otad_inventory_db,
        "CREATE UNIQUE INDEX IF NOT EXISTS ota_operations_one_hot_apply "
        "ON ota_operations(kind) WHERE kind='hot_update' AND action='apply' "
        "AND state IN ('writing','rebooting','reconnecting')") != 0)
        return otad_db_init_fail();

    if (otad_exec(g_otad_inventory_db,
        "CREATE TABLE IF NOT EXISTS inventory_files ("
        " path TEXT PRIMARY KEY,"
        " owner_pkg TEXT NOT NULL DEFAULT '',"
        " class TEXT NOT NULL DEFAULT 'unknown',"
        " size INTEGER NOT NULL DEFAULT 0,"
        " mode INTEGER NOT NULL DEFAULT 0,"
        " uid INTEGER NOT NULL DEFAULT 0,"
        " gid INTEGER NOT NULL DEFAULT 0,"
        " mtime INTEGER NOT NULL DEFAULT 0,"
        " ctime INTEGER NOT NULL DEFAULT 0,"
        " dev INTEGER NOT NULL DEFAULT 0,"
        " inode INTEGER NOT NULL DEFAULT 0,"
        " content_sha256 TEXT NOT NULL DEFAULT '',"
        " dir_digest TEXT NOT NULL DEFAULT '',"
        " source TEXT NOT NULL DEFAULT '',"
        " confidence REAL NOT NULL DEFAULT 0,"
        " preserve_policy TEXT NOT NULL DEFAULT 'report_only',"
        " first_seen INTEGER NOT NULL DEFAULT 0,"
        " last_seen INTEGER NOT NULL DEFAULT 0,"
        " notes TEXT NOT NULL DEFAULT '')") != 0)
        return otad_db_init_fail();
    if (otad_exec(g_otad_inventory_db,
        "CREATE TABLE IF NOT EXISTS inventory_unknowns ("
        " path TEXT PRIMARY KEY,"
        " reason TEXT NOT NULL DEFAULT '',"
        " suggested_action TEXT NOT NULL DEFAULT 'report_only',"
        " size INTEGER NOT NULL DEFAULT 0,"
        " mtime INTEGER NOT NULL DEFAULT 0,"
        " first_seen INTEGER NOT NULL DEFAULT 0,"
        " last_seen INTEGER NOT NULL DEFAULT 0,"
        " will_preserve INTEGER NOT NULL DEFAULT 0)") != 0)
        return otad_db_init_fail();
    if (otad_exec(g_otad_inventory_db,
        "CREATE TABLE IF NOT EXISTS inventory_snapshots ("
        " snapshot_id TEXT PRIMARY KEY,"
        " created_at INTEGER NOT NULL DEFAULT 0,"
        " slot TEXT NOT NULL DEFAULT '',"
        " build_id TEXT NOT NULL DEFAULT '',"
        " file_count INTEGER NOT NULL DEFAULT 0,"
        " unknown_count INTEGER NOT NULL DEFAULT 0)") != 0)
        return otad_db_init_fail();
    if (otad_exec(g_otad_inventory_db,
        "CREATE TABLE IF NOT EXISTS inventory_rules ("
        " pattern TEXT PRIMARY KEY,"
        " class TEXT NOT NULL DEFAULT '',"
        " policy TEXT NOT NULL DEFAULT '',"
        " source TEXT NOT NULL DEFAULT '')") != 0)
        return otad_db_init_fail();

    otad_state_set("schema_version", "2");
    if (otad_exec(g_otad_config_db,
        "INSERT OR IGNORE INTO ota_state(key,value,updated_at) VALUES('state','idle',0)") != 0)
        return otad_db_init_fail();
    return 0;
}

void otad_db_close(void)
{
    if (g_otad_config_db) {
        sqlite3_close(g_otad_config_db);
        g_otad_config_db = NULL;
    }
    if (g_otad_inventory_db) {
        sqlite3_close(g_otad_inventory_db);
        g_otad_inventory_db = NULL;
    }
}

int otad_state_set(const char *key, const char *value)
{
    sqlite3_stmt *st;
    int rc;

    if (!key || !value || !g_otad_config_db)
        return -1;
    st = otad_config_prepare(
        "INSERT INTO ota_state(key,value,updated_at) VALUES(?,?,?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at");
    if (!st)
        return -1;
    sqlite3_bind_text(st, 1, key, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, value, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 3, otad_now_s());
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

int otad_state_get(const char *key, char *out, size_t out_len, const char *def)
{
    sqlite3_stmt *st;
    int rc;
    const char *s = def ? def : "";

    if (!out || out_len == 0)
        return -1;
    snprintf(out, out_len, "%s", s);
    if (!key || !g_otad_config_db)
        return -1;
    st = otad_config_prepare("SELECT value FROM ota_state WHERE key=?");
    if (!st)
        return -1;
    sqlite3_bind_text(st, 1, key, -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) {
        s = (const char *)sqlite3_column_text(st, 0);
        snprintf(out, out_len, "%s", s ? s : "");
    }
    sqlite3_finalize(st);
    return 0;
}

int otad_operation_id_ok(const char *operation_id)
{
    size_t i;

    if (!operation_id || strlen(operation_id) != OTAD_OPERATION_ID_LEN ||
        strncmp(operation_id, "ota-", 4))
        return 0;
    for (i = 4; i < OTAD_OPERATION_ID_LEN; i++)
        if (!isxdigit((unsigned char)operation_id[i]))
            return 0;
    return 1;
}

int otad_upload_id_ok(const char *upload_id)
{
    size_t i;

    if (!upload_id || strlen(upload_id) != OTAD_UPLOAD_ID_LEN ||
        strncmp(upload_id, "upl-", 4))
        return 0;
    for (i = 4; i < OTAD_UPLOAD_ID_LEN; i++)
        if (!isxdigit((unsigned char)upload_id[i]))
            return 0;
    return 1;
}

static int otad_operation_state_ok(const char *state)
{
    return state && (!strcmp(state, "validating") || !strcmp(state, "pending") ||
                     !strcmp(state, "writing") ||
                     !strcmp(state, "rebooting") || !strcmp(state, "reconnecting") ||
                     !strcmp(state, "success") || !strcmp(state, "failed"));
}

static sqlite3_stmt *otad_operation_prepare(const char *sql);

static int otad_operation_transition_ok(const char *from, const char *to)
{
    if (!otad_operation_state_ok(from) || !otad_operation_state_ok(to))
        return 0;
    if (!strcmp(from, to))
        return strcmp(from, "success") && strcmp(from, "failed");
    if (!strcmp(from, "validating"))
        return !strcmp(to, "success") || !strcmp(to, "failed");
    if (!strcmp(from, "pending"))
        return !strcmp(to, "writing") || !strcmp(to, "failed");
    if (!strcmp(from, "writing"))
        return !strcmp(to, "rebooting") || !strcmp(to, "failed");
    if (!strcmp(from, "rebooting"))
        return !strcmp(to, "reconnecting") || !strcmp(to, "failed");
    if (!strcmp(from, "reconnecting"))
        return !strcmp(to, "success") || !strcmp(to, "failed");
    return 0;
}

static int otad_notify_failed_operation(const char *operation_id,
                                        int64_t completed_at)
{
    sqlite3_stmt *st = NULL;
    struct json_object *event = NULL;
    struct json_object *detail = NULL;
    struct ubus_context *ctx = g_otad_ubus;
    struct ubus_context *temporary_ctx = NULL;
    struct blob_buf blob = {};
    uint32_t object_id = 0;
    char stable_id[80];
    char dedupe_key[80];
    char title[192];
    char kind[32] = "";
    char action[32] = "";
    char from_version[128] = "";
    char to_version[128] = "";
    char build_id[128] = "";
    char target_slot[16] = "";
    char error_code[160] = "";
    char error_message[512] = "";
    int blob_ready = 0;
    int rc = -1;

    if (!otad_operation_id_ok(operation_id))
        return -1;
    st = otad_operation_prepare(
        "SELECT kind,action,from_version,to_version,build_id,target_slot,"
        "error_code,error_message FROM ota_operations "
        "WHERE operation_id=?1 AND state='failed'");
    if (!st)
        return -1;
    sqlite3_bind_text(st, 1, operation_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_ROW)
        goto done;
    snprintf(kind, sizeof(kind), "%s", sqlite3_column_text(st, 0));
    snprintf(action, sizeof(action), "%s", sqlite3_column_text(st, 1));
    snprintf(from_version, sizeof(from_version), "%s", sqlite3_column_text(st, 2));
    snprintf(to_version, sizeof(to_version), "%s", sqlite3_column_text(st, 3));
    snprintf(build_id, sizeof(build_id), "%s", sqlite3_column_text(st, 4));
    snprintf(target_slot, sizeof(target_slot), "%s", sqlite3_column_text(st, 5));
    snprintf(error_code, sizeof(error_code), "%s", sqlite3_column_text(st, 6));
    snprintf(error_message, sizeof(error_message), "%s", sqlite3_column_text(st, 7));
    sqlite3_finalize(st);
    st = NULL;

    if (!ctx) {
        temporary_ctx = ubus_connect(NULL);
        ctx = temporary_ctx;
    }
    if (!ctx || ubus_lookup_id(ctx, "dreamingwrt.logd", &object_id) != UBUS_STATUS_OK)
        goto done;
    event = json_object_new_object();
    detail = json_object_new_object();
    if (!event || !detail)
        goto done;
    snprintf(stable_id, sizeof(stable_id), "otad-failure-%s", operation_id);
    snprintf(dedupe_key, sizeof(dedupe_key), "application-update:%s", operation_id);
    snprintf(title, sizeof(title), "%s update failed: %s",
             !strcmp(kind, "firmware") ? "Firmware" : "Application",
             error_code[0] ? error_code : "unknown_error");

    otad_json_add_string(detail, "operation_id", operation_id);
    otad_json_add_string(detail, "producer_event_id", stable_id);
    otad_json_add_string(detail, "kind", kind);
    otad_json_add_string(detail, "action", action);
    otad_json_add_string(detail, "from_version", from_version);
    otad_json_add_string(detail, "to_version", to_version);
    otad_json_add_string(detail, "build_id", build_id);
    otad_json_add_string(detail, "target_slot", target_slot);
    otad_json_add_string(detail, "error_code", error_code);
    otad_json_add_string(detail, "error_message", error_message);
    otad_json_add_string(detail, "state_before", "in_progress");
    otad_json_add_string(detail, "state_after", "failed");

    otad_json_add_string(event, "id", stable_id);
    otad_json_add_string(event, "severity", "error");
    otad_json_add_string(event, "category", "system");
    otad_json_add_string(event, "event", "application_update_failed");
    otad_json_add_string(event, "source", "otad.operation");
    otad_json_add_string(event, "title", title);
    otad_json_add_string(event, "target", operation_id);
    otad_json_add_string(event, "state", "active");
    otad_json_add_string(event, "dedupe_key", dedupe_key);
    json_object_object_add(event, "ts", json_object_new_int64(completed_at));
    json_object_object_add(event, "detail_json", detail);
    detail = NULL;

    blob_buf_init(&blob, 0);
    blob_ready = 1;
    if (!blobmsg_add_json_from_string(
            &blob, json_object_to_json_string_ext(event, JSON_C_TO_STRING_PLAIN)))
        goto done;
    rc = ubus_invoke(ctx, object_id, "event_add", blob.head, NULL, NULL, 750);
done:
    if (st)
        sqlite3_finalize(st);
    if (blob_ready)
        blob_buf_free(&blob);
    if (detail)
        json_object_put(detail);
    if (event)
        json_object_put(event);
    if (temporary_ctx)
        ubus_free(temporary_ctx);
    return rc == UBUS_STATUS_OK ? 0 : -1;
}

static int otad_digest_hex_ok(const char *value)
{
    size_t i;

    if (!value || strlen(value) != 64)
        return 0;
    for (i = 0; i < 64; i++)
        if (!isxdigit((unsigned char)value[i]))
            return 0;
    return 1;
}

static int otad_signing_key_id_ok(const char *value)
{
    const unsigned char *p;
    size_t len = value ? strlen(value) : 0;

    if (!len || len > OTAD_TRUST_KEY_ID_MAX)
        return 0;
    for (p = (const unsigned char *)value; *p; p++)
        if (!isalnum(*p) && *p != '.' && *p != '_' && *p != '-')
            return 0;
    return 1;
}

static int otad_operation_generate_id(char out[OTAD_OPERATION_ID_LEN + 1])
{
    unsigned char random_bytes[16];
    int fd;
    ssize_t got;

    fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return -1;
    do {
        got = read(fd, random_bytes, sizeof(random_bytes));
    } while (got < 0 && errno == EINTR);
    close(fd);
    if (got != (ssize_t)sizeof(random_bytes))
        return -1;
    snprintf(out, OTAD_OPERATION_ID_LEN + 1,
             "ota-%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
             random_bytes[0], random_bytes[1], random_bytes[2], random_bytes[3],
             random_bytes[4], random_bytes[5], random_bytes[6], random_bytes[7],
             random_bytes[8], random_bytes[9], random_bytes[10], random_bytes[11],
             random_bytes[12], random_bytes[13], random_bytes[14], random_bytes[15]);
    return 0;
}

static int otad_operation_name_ok(const char *value)
{
    const unsigned char *p;
    size_t len = value ? strlen(value) : 0;

    if (!len || len >= 32)
        return 0;
    for (p = (const unsigned char *)value; *p; p++)
        if (!isalnum(*p) && *p != '_' && *p != '-')
            return 0;
    return 1;
}

static sqlite3_stmt *otad_operation_prepare(const char *sql)
{
    return otad_inventory_prepare(sql);
}

int otad_operation_create(const char *kind, const char *action,
                          const char *upload_id, struct json_object *options,
                          char operation_id[OTAD_OPERATION_ID_LEN + 1],
                          char *error, size_t error_len)
{
    sqlite3_stmt *st;
    const char *options_text;
    int64_t now = otad_now_s();
    int rc;
    int attempts;

    if (!g_otad_inventory_db || !operation_id || !otad_operation_name_ok(kind) ||
        !otad_operation_name_ok(action) ||
        (upload_id && upload_id[0] && !otad_upload_id_ok(upload_id))) {
        otad_db_error(error, error_len, "operation_contract_invalid");
        return -1;
    }
    if (!options || !json_object_is_type(options, json_type_object))
        options_text = "{}";
    else
        options_text = json_object_to_json_string_ext(options, JSON_C_TO_STRING_PLAIN);
    if (!options_text || strlen(options_text) >= OTAD_OPERATION_OPTIONS_MAX) {
        otad_db_error(error, error_len, "operation_options_too_large");
        return -1;
    }
    for (attempts = 0; attempts < 8; attempts++) {
        if (otad_operation_generate_id(operation_id) != 0) {
            otad_db_error(error, error_len, "operation_id_generation_failed");
            return -1;
        }
        st = otad_operation_prepare(
            "INSERT INTO ota_operations(operation_id,kind,action,upload_id,state,progress,"
            "options_json,result_json,created_at,started_at,updated_at) "
            "VALUES(?1,?2,?3,?4,'validating',0,?5,'{}',?6,?6,?6)");
        if (!st) {
            otad_db_error(error, error_len, "operation_db_prepare_failed");
            return -1;
        }
        sqlite3_bind_text(st, 1, operation_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, kind, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 3, action, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 4, upload_id ? upload_id : "", -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 5, options_text, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 6, now);
        rc = sqlite3_step(st);
        sqlite3_finalize(st);
        if (rc == SQLITE_DONE)
            return 0;
        if (rc == SQLITE_CONSTRAINT && !strcmp(kind, "firmware") &&
            !strcmp(action, "apply")) {
            otad_db_error(error, error_len, "firmware_operation_in_progress");
            return -2;
        }
        if (rc != SQLITE_CONSTRAINT)
            break;
    }
    operation_id[0] = '\0';
    otad_db_error(error, error_len, "operation_create_failed");
    return -1;
}

int otad_operation_set_worker_pid(const char *operation_id, pid_t worker_pid)
{
    sqlite3_stmt *st;
    int rc;

    if (!otad_operation_id_ok(operation_id) || worker_pid <= 1)
        return -1;
    st = otad_operation_prepare(
        "UPDATE ota_operations SET worker_pid=?1,updated_at=?2 "
        "WHERE operation_id=?3 AND state IN ('validating','pending','writing')");
    if (!st)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)worker_pid);
    sqlite3_bind_int64(st, 2, otad_now_s());
    sqlite3_bind_text(st, 3, operation_id, -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE && sqlite3_changes(g_otad_inventory_db) == 1 ? 0 : -1;
}

int otad_operation_claim_apply(const char *operation_id)
{
    sqlite3_stmt *st;
    int rc;

    if (!otad_operation_id_ok(operation_id))
        return -1;
    st = otad_operation_prepare(
        "UPDATE ota_operations SET action='apply',state='writing',progress=25,"
        "worker_pid=0,error_code='',error_message='',updated_at=?1 "
        "WHERE operation_id=?2 AND kind='firmware' AND action='preflight' "
        "AND state='pending' AND authenticity_verified=1 "
        "AND target_compatible=1 AND policy_passed=1 "
        "AND manifest_digest<>'' AND signing_key_id<>'' "
        "AND trust_policy_version>0 AND trust_policy_digest<>'' "
        "AND device_identity_digest<>'' AND topology_digest<>'' "
        "AND source_size>=1048576 AND length(source_sha256)=64 "
        "AND source_sha256 NOT GLOB '*[^0-9A-Fa-f]*' "
        "AND target_slot IN ('A','B') "
        "AND length(manifest_digest)=64 AND manifest_digest NOT GLOB '*[^0-9A-Fa-f]*' "
        "AND length(signing_key_id)<=128 AND signing_key_id NOT GLOB '*[^0-9A-Za-z._-]*' "
        "AND length(trust_policy_digest)=64 "
        "AND trust_policy_digest NOT GLOB '*[^0-9A-Fa-f]*' "
        "AND length(device_identity_digest)=64 "
        "AND device_identity_digest NOT GLOB '*[^0-9A-Fa-f]*' "
        "AND length(topology_digest)=64 "
        "AND topology_digest NOT GLOB '*[^0-9A-Fa-f]*'");
    if (!st)
        return -1;
    sqlite3_bind_int64(st, 1, otad_now_s());
    sqlite3_bind_text(st, 2, operation_id, -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc == SQLITE_CONSTRAINT)
        return -2;
    return rc == SQLITE_DONE && sqlite3_changes(g_otad_inventory_db) == 1 ? 0 : -1;
}

int otad_operation_get_work(const char *operation_id,
                            struct otad_operation_work *work)
{
    sqlite3_stmt *st;
    int rc;

    if (!work || !otad_operation_id_ok(operation_id))
        return -1;
    memset(work, 0, sizeof(*work));
    st = otad_operation_prepare(
        "SELECT operation_id,kind,action,upload_id,state,options_json,source_size,source_sha256,target_slot,"
        "manifest_digest,signing_key_id,trust_policy_version,trust_policy_digest,device_identity_digest,"
        "topology_digest,authenticity_verified,target_compatible,policy_passed "
        "FROM ota_operations WHERE operation_id=?1");
    if (!st)
        return -1;
    sqlite3_bind_text(st, 1, operation_id, -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) {
        snprintf(work->operation_id, sizeof(work->operation_id), "%s",
                 sqlite3_column_text(st, 0));
        snprintf(work->kind, sizeof(work->kind), "%s", sqlite3_column_text(st, 1));
        snprintf(work->action, sizeof(work->action), "%s", sqlite3_column_text(st, 2));
        snprintf(work->upload_id, sizeof(work->upload_id), "%s", sqlite3_column_text(st, 3));
        snprintf(work->state, sizeof(work->state), "%s", sqlite3_column_text(st, 4));
        snprintf(work->options_json, sizeof(work->options_json), "%s",
                 sqlite3_column_text(st, 5));
        work->source_size = (uint64_t)sqlite3_column_int64(st, 6);
        snprintf(work->source_sha256, sizeof(work->source_sha256), "%s",
                 sqlite3_column_text(st, 7));
        snprintf(work->target_slot, sizeof(work->target_slot), "%s",
                 sqlite3_column_text(st, 8));
        snprintf(work->manifest_digest, sizeof(work->manifest_digest), "%s",
                 sqlite3_column_text(st, 9));
        snprintf(work->signing_key_id, sizeof(work->signing_key_id), "%s",
                 sqlite3_column_text(st, 10));
        work->trust_policy_version = sqlite3_column_int(st, 11);
        snprintf(work->trust_policy_digest, sizeof(work->trust_policy_digest), "%s",
                 sqlite3_column_text(st, 12));
        snprintf(work->device_identity_digest,
                 sizeof(work->device_identity_digest), "%s",
                 sqlite3_column_text(st, 13));
        snprintf(work->topology_digest, sizeof(work->topology_digest), "%s",
                 sqlite3_column_text(st, 14));
        work->authenticity_verified = sqlite3_column_int(st, 15) == 1;
        work->target_compatible = sqlite3_column_int(st, 16) == 1;
        work->policy_passed = sqlite3_column_int(st, 17) == 1;
    }
    sqlite3_finalize(st);
    return rc == SQLITE_ROW ? 0 : -1;
}

int otad_operation_update(const char *operation_id, const char *state,
                          int progress, const char *error_code,
                          const char *error_message,
                          struct json_object *result)
{
    sqlite3_stmt *read_st;
    sqlite3_stmt *write_st;
    char current[32] = "";
    const char *result_text = NULL;
    int64_t now = otad_now_s();
    int terminal;
    int rc;

    if (!otad_operation_id_ok(operation_id) || !otad_operation_state_ok(state) ||
        progress < 0 || progress > 100)
        return -1;
    if (result) {
        if (!json_object_is_type(result, json_type_object))
            return -1;
        result_text = json_object_to_json_string_ext(result, JSON_C_TO_STRING_PLAIN);
        if (!result_text || strlen(result_text) > OTAD_MAX_JSON_BYTES)
            return -1;
    }
    read_st = otad_operation_prepare(
        "SELECT state FROM ota_operations WHERE operation_id=?1");
    if (!read_st)
        return -1;
    sqlite3_bind_text(read_st, 1, operation_id, -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(read_st);
    if (rc == SQLITE_ROW)
        snprintf(current, sizeof(current), "%s", sqlite3_column_text(read_st, 0));
    sqlite3_finalize(read_st);
    if (rc != SQLITE_ROW || !otad_operation_transition_ok(current, state))
        return -1;
    terminal = !strcmp(state, "success") || !strcmp(state, "failed");
    write_st = otad_operation_prepare(
        "UPDATE ota_operations SET state=?1,progress=?2,worker_pid=CASE WHEN ?3 THEN 0 ELSE worker_pid END,"
        "error_code=CASE WHEN ?4 IS NULL THEN error_code ELSE ?4 END,"
        "error_message=CASE WHEN ?5 IS NULL THEN error_message ELSE ?5 END,"
        "result_json=CASE WHEN ?6 IS NULL THEN result_json ELSE ?6 END,"
        "updated_at=?7,completed_at=CASE WHEN ?3 THEN ?7 ELSE completed_at END "
        "WHERE operation_id=?8 AND state=?9 "
        "AND (?1!='pending' OR (authenticity_verified=1 AND target_compatible=1 "
        "AND policy_passed=1 AND length(manifest_digest)=64 "
        "AND length(signing_key_id)>0 AND trust_policy_version>0 "
        "AND length(trust_policy_digest)=64 AND length(device_identity_digest)=64 "
        "AND length(topology_digest)=64))");
    if (!write_st)
        return -1;
    sqlite3_bind_text(write_st, 1, state, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(write_st, 2, progress);
    sqlite3_bind_int(write_st, 3, terminal);
    if (error_code)
        sqlite3_bind_text(write_st, 4, error_code, -1, SQLITE_TRANSIENT);
    else
        sqlite3_bind_null(write_st, 4);
    if (error_message)
        sqlite3_bind_text(write_st, 5, error_message, -1, SQLITE_TRANSIENT);
    else
        sqlite3_bind_null(write_st, 5);
    if (result_text)
        sqlite3_bind_text(write_st, 6, result_text, -1, SQLITE_TRANSIENT);
    else
        sqlite3_bind_null(write_st, 6);
    sqlite3_bind_int64(write_st, 7, now);
    sqlite3_bind_text(write_st, 8, operation_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(write_st, 9, current, -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(write_st);
    sqlite3_finalize(write_st);
    if (rc != SQLITE_DONE || sqlite3_changes(g_otad_inventory_db) != 1)
        return -1;
    if (!strcmp(state, "failed") &&
        otad_notify_failed_operation(operation_id, now) != 0)
        fprintf(stderr,
                "[dreamingwrt-otad] logd bridge failed for operation=%s\n",
                operation_id);
    return 0;
}

int otad_operation_set_source(const char *operation_id, uint64_t source_size,
                              const char *source_sha256)
{
    sqlite3_stmt *st;
    int rc;

    if (!otad_operation_id_ok(operation_id) || source_size < OTAD_FIRMWARE_HEADER_BYTES ||
        !otad_digest_hex_ok(source_sha256))
        return -1;
    st = otad_operation_prepare(
        "UPDATE ota_operations SET source_size=?1,source_sha256=?2,updated_at=?3 "
        "WHERE operation_id=?4 AND state='validating' "
        "AND (source_sha256='' OR (source_size=?1 AND source_sha256=?2))");
    if (!st)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)source_size);
    sqlite3_bind_text(st, 2, source_sha256, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 3, otad_now_s());
    sqlite3_bind_text(st, 4, operation_id, -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE && sqlite3_changes(g_otad_inventory_db) == 1 ? 0 : -1;
}

int otad_operation_commit_preflight(const char *operation_id,
                                    const char *from_version,
                                    const char *to_version,
                                    const char *build_id,
                                    const char *target_slot,
                                    const struct otad_trust_binding *binding,
                                    const char *topology_digest,
                                    struct json_object *result)
{
    sqlite3_stmt *st;
    const char *result_text;
    int rc;

    if (!otad_operation_id_ok(operation_id) || !binding ||
        !otad_digest_hex_ok(binding->manifest_digest) ||
        !otad_signing_key_id_ok(binding->signing_key_id) ||
        binding->trust_policy_version < 1 ||
        !otad_digest_hex_ok(binding->trust_policy_digest) ||
        !otad_digest_hex_ok(binding->device_identity_digest) ||
        !binding->authenticity_verified || !binding->target_compatible ||
        !binding->policy_passed || !topology_digest ||
        !otad_digest_hex_ok(topology_digest) || !target_slot ||
        ((target_slot[0] != 'A' && target_slot[0] != 'B') || target_slot[1]) ||
        !result ||
        !json_object_is_type(result, json_type_object))
        return -1;
    result_text = json_object_to_json_string_ext(result, JSON_C_TO_STRING_PLAIN);
    if (!result_text || strlen(result_text) > OTAD_MAX_JSON_BYTES)
        return -1;
    st = otad_operation_prepare(
        "UPDATE ota_operations SET state='pending',progress=20,from_version=?1,to_version=?2,build_id=?3,"
        "target_slot=?4,manifest_digest=?5,signing_key_id=?6,"
        "trust_policy_version=?7,trust_policy_digest=?8,device_identity_digest=?9,"
        "topology_digest=?10,authenticity_verified=?11,target_compatible=?12,policy_passed=?13,"
        "result_json=?14,error_code='',error_message='',updated_at=?15 "
        "WHERE operation_id=?16 AND kind='firmware' AND action='preflight' AND state='validating' "
        "AND source_size>=1048576 AND length(source_sha256)=64 "
        "AND source_sha256 NOT GLOB '*[^0-9A-Fa-f]*' "
        "AND manifest_digest='' AND signing_key_id='' AND trust_policy_version=0 "
        "AND trust_policy_digest='' AND device_identity_digest='' AND topology_digest='' "
        "AND authenticity_verified=0 AND target_compatible=0 AND policy_passed=0");
    if (!st)
        return -1;
    sqlite3_bind_text(st, 1, from_version ? from_version : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, to_version ? to_version : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, build_id ? build_id : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 4, target_slot ? target_slot : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 5, binding->manifest_digest, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 6, binding->signing_key_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 7, binding->trust_policy_version);
    sqlite3_bind_text(st, 8, binding->trust_policy_digest, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 9, binding->device_identity_digest, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 10, topology_digest, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 11, binding->authenticity_verified);
    sqlite3_bind_int(st, 12, binding->target_compatible);
    sqlite3_bind_int(st, 13, binding->policy_passed);
    sqlite3_bind_text(st, 14, result_text, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 15, otad_now_s());
    sqlite3_bind_text(st, 16, operation_id, -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE && sqlite3_changes(g_otad_inventory_db) == 1 ? 0 : -1;
}

/*
 * The hot-update twin of otad_operation_commit_preflight(). A hot package needs
 * no slot and no A/B topology, so those two columns stay empty and the checks
 * that apply to them are dropped; every trust field is still required, because
 * the apply claim below refuses to move without them.
 */
int otad_operation_commit_hot_preflight(const char *operation_id,
                                        const char *from_version,
                                        const char *to_version,
                                        const char *package_id,
                                        const struct otad_trust_binding *binding,
                                        struct json_object *result)
{
    sqlite3_stmt *st;
    const char *result_text;
    int rc;

    if (!otad_operation_id_ok(operation_id) || !binding ||
        !otad_digest_hex_ok(binding->manifest_digest) ||
        !otad_signing_key_id_ok(binding->signing_key_id) ||
        binding->trust_policy_version < 1 ||
        !otad_digest_hex_ok(binding->trust_policy_digest) ||
        !otad_digest_hex_ok(binding->device_identity_digest) ||
        !binding->authenticity_verified || !binding->target_compatible ||
        !binding->policy_passed || !result ||
        !json_object_is_type(result, json_type_object))
        return -1;
    result_text = json_object_to_json_string_ext(result, JSON_C_TO_STRING_PLAIN);
    if (!result_text || strlen(result_text) > OTAD_MAX_JSON_BYTES)
        return -1;
    st = otad_operation_prepare(
        "UPDATE ota_operations SET state='pending',progress=20,from_version=?1,to_version=?2,"
        "build_id=?3,manifest_digest=?4,signing_key_id=?5,"
        "trust_policy_version=?6,trust_policy_digest=?7,device_identity_digest=?8,"
        "authenticity_verified=?9,target_compatible=?10,policy_passed=?11,"
        "result_json=?12,error_code='',error_message='',updated_at=?13 "
        "WHERE operation_id=?14 AND kind='hot_update' AND action='preflight' "
        "AND state='validating' "
        "AND source_size>=1048576 AND length(source_sha256)=64 "
        "AND source_sha256 NOT GLOB '*[^0-9A-Fa-f]*' "
        "AND manifest_digest='' AND signing_key_id='' AND trust_policy_version=0 "
        "AND trust_policy_digest='' AND device_identity_digest='' "
        "AND authenticity_verified=0 AND target_compatible=0 AND policy_passed=0");
    if (!st)
        return -1;
    sqlite3_bind_text(st, 1, from_version ? from_version : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, to_version ? to_version : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, package_id ? package_id : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 4, binding->manifest_digest, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 5, binding->signing_key_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 6, binding->trust_policy_version);
    sqlite3_bind_text(st, 7, binding->trust_policy_digest, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 8, binding->device_identity_digest, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 9, binding->authenticity_verified);
    sqlite3_bind_int(st, 10, binding->target_compatible);
    sqlite3_bind_int(st, 11, binding->policy_passed);
    sqlite3_bind_text(st, 12, result_text, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 13, otad_now_s());
    sqlite3_bind_text(st, 14, operation_id, -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE && sqlite3_changes(g_otad_inventory_db) == 1 ? 0 : -1;
}

/*
 * Claim a verified hot preflight for writing. Mirrors otad_operation_claim_apply()
 * minus the slot and topology conditions, and like it this is the single point
 * where a hot apply becomes exclusive: the partial unique index on kind means a
 * second concurrent claim fails rather than racing the first one into the
 * filesystem.
 */
int otad_operation_claim_hot_apply(const char *operation_id)
{
    sqlite3_stmt *st;
    int rc;

    if (!otad_operation_id_ok(operation_id))
        return -1;
    st = otad_operation_prepare(
        "UPDATE ota_operations SET action='apply',state='writing',progress=25,"
        "worker_pid=0,error_code='',error_message='',updated_at=?1 "
        "WHERE operation_id=?2 AND kind='hot_update' AND action='preflight' "
        "AND state='pending' AND authenticity_verified=1 "
        "AND target_compatible=1 AND policy_passed=1 "
        "AND manifest_digest<>'' AND signing_key_id<>'' "
        "AND trust_policy_version>0 AND trust_policy_digest<>'' "
        "AND device_identity_digest<>'' "
        "AND source_size>=1048576 AND length(source_sha256)=64 "
        "AND source_sha256 NOT GLOB '*[^0-9A-Fa-f]*' "
        "AND length(manifest_digest)=64 AND manifest_digest NOT GLOB '*[^0-9A-Fa-f]*' "
        "AND length(signing_key_id)<=128 AND signing_key_id NOT GLOB '*[^0-9A-Za-z._-]*' "
        "AND length(trust_policy_digest)=64 "
        "AND trust_policy_digest NOT GLOB '*[^0-9A-Fa-f]*' "
        "AND length(device_identity_digest)=64 "
        "AND device_identity_digest NOT GLOB '*[^0-9A-Fa-f]*'");
    if (!st)
        return -1;
    sqlite3_bind_int64(st, 1, otad_now_s());
    sqlite3_bind_text(st, 2, operation_id, -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc == SQLITE_CONSTRAINT)
        return -2;
    return rc == SQLITE_DONE && sqlite3_changes(g_otad_inventory_db) == 1 ? 0 : -1;
}

int otad_operation_find_active_firmware_apply(
    char operation_id[OTAD_OPERATION_ID_LEN + 1])
{
    sqlite3_stmt *st;
    int rc;

    if (!operation_id)
        return -1;
    operation_id[0] = '\0';
    st = otad_operation_prepare(
        "SELECT operation_id FROM ota_operations WHERE kind='firmware' AND action='apply' "
        "AND state IN ('validating','pending','writing','rebooting','reconnecting') "
        "ORDER BY created_at DESC LIMIT 1");
    if (!st)
        return -1;
    rc = sqlite3_step(st);
    if (rc == SQLITE_ROW)
        snprintf(operation_id, OTAD_OPERATION_ID_LEN + 1, "%s",
                 sqlite3_column_text(st, 0));
    sqlite3_finalize(st);
    return rc == SQLITE_ROW ? 0 : 1;
}

int otad_operation_complete_confirmed_boot(
    const char *target_slot, const char *expected_operation_id,
    const char *expected_build_id,
    char operation_id[OTAD_OPERATION_ID_LEN + 1])
{
    sqlite3_stmt *st;
    int64_t now = otad_now_s();
    int rc;

    if (!target_slot || (strcmp(target_slot, "A") && strcmp(target_slot, "B")) ||
        !operation_id ||
        (expected_operation_id && expected_operation_id[0] &&
         !otad_operation_id_ok(expected_operation_id)) ||
        (expected_build_id && strlen(expected_build_id) >= OTAD_MAX_TEXT))
        return -1;
    operation_id[0] = '\0';

    /*
     * The partial unique index permits only one live firmware apply. Keep the
     * slot and optional persisted operation id in this same UPDATE so a boot
     * confirmation can never complete an unrelated or already terminal row.
     */
    st = otad_operation_prepare(
        "UPDATE ota_operations SET state='success',progress=100,worker_pid=0,"
        "error_code='',error_message='',updated_at=?1,completed_at=?1 "
        "WHERE operation_id=(SELECT operation_id FROM ota_operations "
        "WHERE kind='firmware' AND action='apply' AND target_slot=?2 "
        "AND state='rebooting' "
        "AND (?3='' OR operation_id=?3) "
        "AND (?4='' OR build_id=?4) "
        "ORDER BY updated_at DESC,created_at DESC LIMIT 1) "
        "RETURNING operation_id");
    if (!st)
        return -1;
    sqlite3_bind_int64(st, 1, now);
    sqlite3_bind_text(st, 2, target_slot, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, expected_operation_id ? expected_operation_id : "",
                      -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 4, expected_build_id ? expected_build_id : "",
                      -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(st);
    if (rc == SQLITE_ROW)
        snprintf(operation_id, OTAD_OPERATION_ID_LEN + 1, "%s",
                 sqlite3_column_text(st, 0));
    if (rc == SQLITE_ROW)
        rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (operation_id[0] && rc == SQLITE_DONE)
        return 0;
    return rc == SQLITE_DONE ? 1 : -1;
}

int otad_operation_complete_automatic_rollback(
    const char *target_slot, const char *expected_operation_id,
    const char *error_code, const char *error_message,
    char operation_id[OTAD_OPERATION_ID_LEN + 1])
{
    sqlite3_stmt *st;
    int64_t now = otad_now_s();
    int rc;

    const unsigned char *p;

    if (!target_slot || (strcmp(target_slot, "A") && strcmp(target_slot, "B")) ||
        !operation_id || !error_code || !error_code[0] ||
        strlen(error_code) >= OTAD_MAX_TEXT ||
        (error_message && strlen(error_message) >= OTAD_MAX_TEXT) ||
        (expected_operation_id && expected_operation_id[0] &&
         !otad_operation_id_ok(expected_operation_id)))
        return -1;
    for (p = (const unsigned char *)error_code; *p; p++)
        if (*p < 0x20 || *p == 0x7f)
            return -1;
    for (p = (const unsigned char *)(error_message ? error_message : ""); *p; p++)
        if ((*p < 0x20 && *p != '\t' && *p != '\n' && *p != '\r') ||
            *p == 0x7f)
            return -1;
    operation_id[0] = '\0';
    st = otad_operation_prepare(
        "UPDATE ota_operations SET state='failed',progress=100,worker_pid=0,"
        "error_code=?1,error_message=?2,updated_at=?3,completed_at=?3 "
        "WHERE operation_id=(SELECT operation_id FROM ota_operations "
        "WHERE kind='firmware' AND action='apply' AND target_slot=?4 "
        "AND state IN ('rebooting','reconnecting') "
        "AND (?5='' OR operation_id=?5 OR 1=(SELECT COUNT(*) FROM ota_operations "
        "WHERE kind='firmware' AND action='apply' AND target_slot=?4 "
        "AND state IN ('rebooting','reconnecting'))) "
        "ORDER BY updated_at DESC,created_at DESC LIMIT 1) "
        "RETURNING operation_id");
    if (!st)
        return -1;
    sqlite3_bind_text(st, 1, error_code, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, error_message ? error_message : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 3, now);
    sqlite3_bind_text(st, 4, target_slot, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 5, expected_operation_id ? expected_operation_id : "",
                      -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(st);
    if (rc == SQLITE_ROW)
        snprintf(operation_id, OTAD_OPERATION_ID_LEN + 1, "%s",
                 sqlite3_column_text(st, 0));
    if (rc == SQLITE_ROW)
        rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (operation_id[0] && rc == SQLITE_DONE)
        return 0;
    return rc == SQLITE_DONE ? 1 : -1;
}

static struct json_object *otad_operation_row_json(sqlite3_stmt *st)
{
    struct json_object *o = json_object_new_object();
    struct json_object *result = NULL;
    const char *state = (const char *)sqlite3_column_text(st, 4);
    const char *result_text = (const char *)sqlite3_column_text(st, 14);
    const char *error_code = (const char *)sqlite3_column_text(st, 15);
    const char *error_message = (const char *)sqlite3_column_text(st, 16);
    int terminal = state && (!strcmp(state, "success") || !strcmp(state, "failed"));

    json_object_object_add(o, "ok", json_object_new_boolean(1));
    otad_json_add_string(o, "operation_id", (const char *)sqlite3_column_text(st, 0));
    otad_json_add_string(o, "kind", (const char *)sqlite3_column_text(st, 1));
    otad_json_add_string(o, "action", (const char *)sqlite3_column_text(st, 2));
    otad_json_add_string(o, "upload_id", (const char *)sqlite3_column_text(st, 3));
    otad_json_add_string(o, "state", state);
    otad_json_add_string(o, "phase", state && !strcmp(state, "success") ? "completed" : state);
    json_object_object_add(o, "progress", json_object_new_int(sqlite3_column_int(st, 5)));
    json_object_object_add(o, "terminal", json_object_new_boolean(terminal));
    json_object_object_add(o, "source_size", json_object_new_int64(sqlite3_column_int64(st, 6)));
    otad_json_add_string(o, "source_sha256", (const char *)sqlite3_column_text(st, 7));
    otad_json_add_string(o, "from_version", (const char *)sqlite3_column_text(st, 8));
    otad_json_add_string(o, "to_version", (const char *)sqlite3_column_text(st, 9));
    otad_json_add_string(o, "build_id", (const char *)sqlite3_column_text(st, 10));
    otad_json_add_string(o, "target_slot", (const char *)sqlite3_column_text(st, 11));
    otad_json_add_string(o, "manifest_digest", (const char *)sqlite3_column_text(st, 18));
    otad_json_add_string(o, "signing_key_id", (const char *)sqlite3_column_text(st, 19));
    json_object_object_add(o, "trust_policy_version",
                           json_object_new_int(sqlite3_column_int(st, 20)));
    otad_json_add_string(o, "trust_policy_digest", (const char *)sqlite3_column_text(st, 21));
    otad_json_add_string(o, "device_identity_digest", (const char *)sqlite3_column_text(st, 22));
    otad_json_add_string(o, "topology_digest", (const char *)sqlite3_column_text(st, 23));
    json_object_object_add(o, "authenticity_verified",
                           json_object_new_boolean(sqlite3_column_int(st, 24) == 1));
    json_object_object_add(o, "target_compatible",
                           json_object_new_boolean(sqlite3_column_int(st, 25) == 1));
    json_object_object_add(o, "policy_passed",
                           json_object_new_boolean(sqlite3_column_int(st, 26) == 1));
    json_object_object_add(o, "created_at", json_object_new_int64(sqlite3_column_int64(st, 12)));
    json_object_object_add(o, "updated_at", json_object_new_int64(sqlite3_column_int64(st, 13)));
    json_object_object_add(o, "completed_at", json_object_new_int64(sqlite3_column_int64(st, 17)));
    if (result_text && result_text[0])
        result = json_tokener_parse(result_text);
    if (!result || !json_object_is_type(result, json_type_object)) {
        if (result)
            json_object_put(result);
        result = json_object_new_object();
    }
    json_object_object_add(o, "result", result);
    if ((error_code && error_code[0]) || (error_message && error_message[0])) {
        struct json_object *error = json_object_new_object();
        otad_json_add_string(error, "code", error_code);
        otad_json_add_string(error, "message", error_message);
        json_object_object_add(o, "error", error);
    } else {
        json_object_object_add(o, "error", NULL);
    }
    json_object_object_add(o, "poll_after_ms", json_object_new_int(terminal ? 0 : 1000));
    return o;
}

struct json_object *otad_operation_status(struct json_object *body)
{
    const char *operation_id = otad_json_str(body, "operation_id", "");
    sqlite3_stmt *st;
    struct json_object *o;
    int rc;

    if (!otad_operation_id_ok(operation_id))
        return otad_error("operation_id_invalid", "a server-generated operation_id is required");
    st = otad_operation_prepare(
        "SELECT operation_id,kind,action,upload_id,state,progress,source_size,source_sha256,"
        "from_version,to_version,build_id,target_slot,created_at,updated_at,result_json,"
        "error_code,error_message,completed_at,manifest_digest,signing_key_id,trust_policy_version,"
        "trust_policy_digest,device_identity_digest,topology_digest,"
        "authenticity_verified,target_compatible,policy_passed "
        "FROM ota_operations WHERE operation_id=?1");
    if (!st)
        return otad_error("operation_query_failed", "failed to prepare operation query");
    sqlite3_bind_text(st, 1, operation_id, -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(st);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(st);
        return otad_error("operation_not_found", "operation_id does not exist");
    }
    o = otad_operation_row_json(st);
    sqlite3_finalize(st);
    return o;
}

void otad_operations_reconcile_workers(void)
{
    sqlite3_stmt *st;
    struct {
        char id[OTAD_OPERATION_ID_LEN + 1];
        pid_t pid;
    } pending[32];
    size_t count = 0;
    size_t i;

    st = otad_operation_prepare(
        "SELECT operation_id,worker_pid FROM ota_operations "
        "WHERE state IN ('validating','writing') ORDER BY updated_at LIMIT 32");
    if (!st)
        return;
    while (count < sizeof(pending) / sizeof(pending[0]) &&
           sqlite3_step(st) == SQLITE_ROW) {
        snprintf(pending[count].id, sizeof(pending[count].id), "%s",
                 sqlite3_column_text(st, 0));
        pending[count].pid = (pid_t)sqlite3_column_int64(st, 1);
        count++;
    }
    sqlite3_finalize(st);
    for (i = 0; i < count; i++) {
        int worker_matches = 0;

        if (pending[i].pid > 1 &&
            (kill(pending[i].pid, 0) == 0 || errno == EPERM)) {
            char path[64];
            char cmdline[512];
            int fd;
            ssize_t got;

            snprintf(path, sizeof(path), "/proc/%ld/cmdline", (long)pending[i].pid);
            fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
            if (fd >= 0) {
                do {
                    got = read(fd, cmdline, sizeof(cmdline) - 1);
                } while (got < 0 && errno == EINTR);
                close(fd);
                if (got > 0) {
                    size_t j;

                    cmdline[got] = '\0';
                    for (j = 0; j < (size_t)got; j++)
                        if (!cmdline[j])
                            cmdline[j] = ' ';
                    if (strstr(cmdline, "dreamingwrt-otad") &&
                        strstr(cmdline, "--operation-worker") &&
                        strstr(cmdline, pending[i].id))
                        worker_matches = 1;
                }
            }
        }
        if (worker_matches)
            continue;
        (void)otad_operation_update(pending[i].id, "failed", 100,
                                    "operation_worker_interrupted",
                                    "the validation or slot-writing worker is no longer running",
                                    NULL);
    }
}

int otad_inventory_replace_file(const char *path, const char *owner_pkg,
                                const char *class_name, const struct stat *st,
                                const char *source, const char *preserve_policy,
                                const char *reason)
{
    sqlite3_stmt *q;
    int rc;
    int64_t now = otad_now_s();

    if (!path || !class_name || !st || !g_otad_inventory_db)
        return -1;
    q = otad_inventory_prepare(
        "INSERT INTO inventory_files(path,owner_pkg,class,size,mode,uid,gid,mtime,ctime,dev,inode,"
        "source,confidence,preserve_policy,first_seen,last_seen,notes) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
        "ON CONFLICT(path) DO UPDATE SET owner_pkg=excluded.owner_pkg,class=excluded.class,"
        "size=excluded.size,mode=excluded.mode,uid=excluded.uid,gid=excluded.gid,"
        "mtime=excluded.mtime,ctime=excluded.ctime,dev=excluded.dev,inode=excluded.inode,"
        "source=excluded.source,confidence=excluded.confidence,preserve_policy=excluded.preserve_policy,"
        "last_seen=excluded.last_seen,notes=excluded.notes");
    if (!q)
        return -1;
    sqlite3_bind_text(q, 1, path, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(q, 2, owner_pkg ? owner_pkg : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(q, 3, class_name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(q, 4, (sqlite3_int64)st->st_size);
    sqlite3_bind_int(q, 5, (int)st->st_mode);
    sqlite3_bind_int(q, 6, (int)st->st_uid);
    sqlite3_bind_int(q, 7, (int)st->st_gid);
    sqlite3_bind_int64(q, 8, (sqlite3_int64)st->st_mtime);
    sqlite3_bind_int64(q, 9, (sqlite3_int64)st->st_ctime);
    sqlite3_bind_int64(q, 10, (sqlite3_int64)st->st_dev);
    sqlite3_bind_int64(q, 11, (sqlite3_int64)st->st_ino);
    sqlite3_bind_text(q, 12, source ? source : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_double(q, 13, owner_pkg && owner_pkg[0] ? 1.0 : 0.5);
    sqlite3_bind_text(q, 14, preserve_policy ? preserve_policy : "report_only", -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(q, 15, now);
    sqlite3_bind_int64(q, 16, now);
    sqlite3_bind_text(q, 17, reason ? reason : "", -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(q);
    sqlite3_finalize(q);
    return rc == SQLITE_DONE ? 0 : -1;
}

int otad_inventory_clear_unknowns(void)
{
    return otad_exec(g_otad_inventory_db, "DELETE FROM inventory_unknowns");
}

int otad_inventory_add_unknown(const char *path, const char *reason,
                               const char *suggested_action, const struct stat *st,
                               int will_preserve)
{
    sqlite3_stmt *q;
    int rc;
    int64_t now = otad_now_s();

    if (!path || !st || !g_otad_inventory_db)
        return -1;
    q = otad_inventory_prepare(
        "INSERT INTO inventory_unknowns(path,reason,suggested_action,size,mtime,first_seen,last_seen,will_preserve) "
        "VALUES(?,?,?,?,?,?,?,?) "
        "ON CONFLICT(path) DO UPDATE SET reason=excluded.reason,suggested_action=excluded.suggested_action,"
        "size=excluded.size,mtime=excluded.mtime,last_seen=excluded.last_seen,will_preserve=excluded.will_preserve");
    if (!q)
        return -1;
    sqlite3_bind_text(q, 1, path, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(q, 2, reason ? reason : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(q, 3, suggested_action ? suggested_action : "report_only", -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(q, 4, (sqlite3_int64)st->st_size);
    sqlite3_bind_int64(q, 5, (sqlite3_int64)st->st_mtime);
    sqlite3_bind_int64(q, 6, now);
    sqlite3_bind_int64(q, 7, now);
    sqlite3_bind_int(q, 8, will_preserve ? 1 : 0);
    rc = sqlite3_step(q);
    sqlite3_finalize(q);
    return rc == SQLITE_DONE ? 0 : -1;
}

/*
 * Force everything written so far all the way onto the disk.
 *
 * The operation trail is the only record of who asked for a firmware write and
 * what was decided, and the write path ends in a reboot. In WAL mode with the
 * default synchronous setting, a row that was committed a moment earlier can
 * still be sitting in the write-ahead log when the machine goes down, which is
 * exactly the case where the record matters most. Truncating the WAL and
 * fsyncing the database file leaves nothing pending.
 *
 * Best effort by design: failing to flush must not abort an upgrade that is
 * otherwise fine, so the result is reported and the caller decides.
 */
static int otad_db_checkpoint_sync(sqlite3 *db, const char *path)
{
    int rc = 0;
    int fd;

    if (!db || !path)
        return -1;
    if (otad_exec(db, "PRAGMA wal_checkpoint(TRUNCATE)") != 0)
        rc = -1;
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
        if (fsync(fd) != 0)
            rc = -1;
        close(fd);
    } else {
        rc = -1;
    }
    return rc;
}

int otad_db_persist_now(void)
{
    int rc = 0;

    if (otad_db_checkpoint_sync(g_otad_config_db, OTAD_CONFIG_DB_PATH) != 0)
        rc = -1;
    if (otad_db_checkpoint_sync(g_otad_inventory_db, OTAD_INVENTORY_DB_PATH) != 0)
        rc = -1;
    return rc;
}
