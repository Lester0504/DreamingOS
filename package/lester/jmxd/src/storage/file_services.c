// SPDX-License-Identifier: GPL-2.0-or-later
/* DreamingWrt file-service configuration and runtime backend. */
#define _GNU_SOURCE

#include "file_services.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <limits.h>
#include <poll.h>
#include <pwd.h>
#include <signal.h>
#include <sqlite3.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <uci.h>
#include <unistd.h>

#ifndef JMX_FILE_SERVICES_DB_PATH
#define JMX_FILE_SERVICES_DB_PATH "/etc/dreamingwrt/config.db"
#endif
#ifndef JMX_SAMBA_CONFIG_PATH
#define JMX_SAMBA_CONFIG_PATH "/etc/config/samba4"
#endif
#ifndef JMX_NFS_CONFIG_PATH
#define JMX_NFS_CONFIG_PATH "/etc/config/nfs"
#endif
#ifndef JMX_SAMBA_INIT_PATH
#define JMX_SAMBA_INIT_PATH "/etc/init.d/samba4"
#endif
#ifndef JMX_NFS_INIT_PATH
#define JMX_NFS_INIT_PATH "/etc/init.d/nfs"
#endif
#ifndef JMX_NFS_EXPORTFS_PATH
#define JMX_NFS_EXPORTFS_PATH "/usr/sbin/exportfs"
#endif
#ifndef JMX_NFS_NATIVE_CONFIG_PATH
#define JMX_NFS_NATIVE_CONFIG_PATH "/etc/exports"
#endif
#ifndef JMX_SAMBA_TESTPARM_PATH
#define JMX_SAMBA_TESTPARM_PATH "/usr/bin/testparm"
#endif
#ifndef JMX_SAMBA_NATIVE_CONFIG_PATH
#define JMX_SAMBA_NATIVE_CONFIG_PATH "/var/etc/smb.conf"
#endif
#ifndef JMX_NFSD_THREADS_PATH
#define JMX_NFSD_THREADS_PATH "/proc/fs/nfsd/threads"
#endif

#ifndef JMX_NFSD_INIT_PATH
#define JMX_NFSD_INIT_PATH "/etc/init.d/nfsd"
#endif
#ifndef JMX_RPC_BIND_INIT_PATH
#define JMX_RPC_BIND_INIT_PATH "/etc/init.d/rpcbind"
#endif
#ifndef JMX_SAMBA_PDBEDIT_PATH
#define JMX_SAMBA_PDBEDIT_PATH "/usr/bin/pdbedit"
#endif

#ifndef JMX_WEBDAV_CONFIG_DIR
#define JMX_WEBDAV_CONFIG_DIR "/etc/config"
#endif

#define FS_API_OK 2000
#define FS_API_ERROR 4000
#define FS_SCHEMA_VERSION 3
#define FS_DB_BUSY_TIMEOUT_MS 5000
#define FS_SERVICE_TIMEOUT_MS 15000
#define FS_SERVICE_OUTPUT_MAX (16U * 1024U)
#define FS_CONFIG_MAX (1024U * 1024U)
#define FS_MAX_PATH 512
#define FS_MAX_ID 64
#define FS_MAX_NAME 80
#define FS_MAX_USERS 64
#define FS_MAX_NFS_OPTIONS 32

struct fs_buffer {
    char *data;
    size_t len;
    size_t cap;
};

struct fs_snapshot {
    char *data;
    size_t len;
    mode_t mode;
    int existed;
};

struct fs_exec_result {
    int exit_code;
    int timed_out;
    int output_truncated;
};

struct fs_samba_share {
    char id[FS_MAX_ID + 1];
    char name[FS_MAX_NAME + 1];
    char path[FS_MAX_PATH + 1];
    int enabled;
    int read_only;
    int browseable;
    int network_discovery;
    int guest_access;
    char *allowed_users_json;
    char note[257];
    int64_t revision;
    int64_t created_at;
    int64_t updated_at;
};

struct fs_nfs_export {
    char id[FS_MAX_ID + 1];
    char path[FS_MAX_PATH + 1];
    char clients[513];
    char options[1025];
    char note[257];
    int enabled;
    int64_t revision;
    int64_t created_at;
    int64_t updated_at;
};

static int fs_nfsd_threads_positive(struct fs_exec_result *result);
static int fs_accounts_schema(sqlite3 *db);
static int fs_dav_schema(sqlite3 *db);
static int fs_dav_any_running(sqlite3 *db);
static int fs_dav_wants_running(sqlite3 *db);
static struct json_object *fs_dav_action(struct json_object *req);
static struct json_object *fs_dav_get(sqlite3 *db);
static int fs_dav_account_refs(sqlite3 *db,const char *login,struct json_object *refs);
static int fs_dav_apply(sqlite3 *db,struct fs_snapshot *old,int *replaced,int start,const char **reason);
static int fs_dav_restore(const struct fs_snapshot *old,int replaced,int running);
static int fs_ftp_schema(sqlite3 *db);
static int fs_ftp_installed(void);
static int fs_ftp_running(void);
static int fs_ftp_wants_running(sqlite3 *db);
static struct json_object *fs_ftp_get(sqlite3 *db);
static struct json_object *fs_ftp_action(struct json_object *req);
static int fs_ftp_account_refs(sqlite3 *db,const char *login,struct json_object *refs);
static int fs_ftp_apply(sqlite3 *db,struct fs_snapshot *old,int *replaced,int start,const char **reason);
static int fs_ftp_restore(const struct fs_snapshot *old,int replaced,int running);
static void fs_ftp_reconcile(sqlite3 *db);
static int fs_bindings_schema(sqlite3 *db);
static int fs_bindings_seed(sqlite3 *db);
static int fs_binding_update(sqlite3 *db,const char *service,const char *id,const char *path,int enabled,struct json_object *payload);
static int fs_binding_available(sqlite3 *db,const char *service,const char *id,const char *path);
static int fs_binding_target(const char *id,char *path,size_t size);
static struct json_object *fs_binding_identity(const char *path);
static int fs_binding_equal(struct json_object *a,struct json_object *b);
static int fs_binding_pin(const char *id,const char *path,struct json_object *identity,char *target,size_t size);
static int fs_binding_mounted(const char *path);
static void fs_binding_unpin(const char *id);
static int fs_binding_prepare(sqlite3 *db,const char *service,const char *id,const char *path,char *target,size_t size);
static void fs_binding_sweep(sqlite3 *db,const char *service);
static void fs_binding_status(sqlite3 *db,struct json_object *item,const char *service,const char *id,const char *path);

static int fs_operations_schema(sqlite3 *db);
static int fs_operation_receipt(sqlite3 *db, const char *id, int64_t revision, int deleted);
static struct json_object *fs_accounts_data(sqlite3 *db);
static int fs_write_all(int fd, const void *data, size_t len);
static void fs_probe_error(struct fs_exec_result *result, int exit_code);

static int64_t fs_now_s(void)
{
    return (int64_t)time(NULL);
}

static int64_t fs_monotonic_ms(void)
{
    struct timespec value;

    if (clock_gettime(CLOCK_MONOTONIC, &value) != 0)
        return -1;
    return (int64_t)value.tv_sec * 1000 + value.tv_nsec / 1000000;
}

static struct json_object *fs_envelope(int code, struct json_object *data)
{
    struct json_object *root = json_object_new_object();

    if (!root) {
        if (data)
            json_object_put(data);
        return NULL;
    }
    json_object_object_add(root, "code", json_object_new_int(code));
    json_object_object_add(root, "data", data ? data : json_object_new_object());
    return root;
}

static struct json_object *fs_error_detail(const char *error, const char *reason)
{
    struct json_object *data = json_object_new_object();

    json_object_object_add(data, "ok", json_object_new_boolean(0));
    json_object_object_add(data, "error",
                           json_object_new_string(error ? error : "internal_error"));
    json_object_object_add(data, "reason",
                           json_object_new_string(reason ? reason : "internal_error"));
    return data;
}

static struct json_object *fs_error(const char *error, const char *reason)
{
    return fs_envelope(FS_API_ERROR, fs_error_detail(error, reason));
}

static struct json_object *fs_success(struct json_object *data)
{
    if (!data)
        data = json_object_new_object();
    json_object_object_add(data, "ok", json_object_new_boolean(1));
    return fs_envelope(FS_API_OK, data);
}

static const char *fs_sql_text(sqlite3_stmt *st, int column, const char *fallback)
{
    const unsigned char *value = sqlite3_column_text(st, column);

    return value ? (const char *)value : (fallback ? fallback : "");
}

static int fs_sql_exec(sqlite3 *db, const char *sql)
{
    char *message = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &message);

    sqlite3_free(message);
    return rc == SQLITE_OK ? 0 : -1;
}

static int fs_prepare(sqlite3 *db, sqlite3_stmt **st, const char *sql)
{
    return sqlite3_prepare_v2(db, sql, -1, st, NULL) == SQLITE_OK ? 0 : -1;
}

static int fs_step_done(sqlite3_stmt *st)
{
    return sqlite3_step(st) == SQLITE_DONE ? 0 : -1;
}

static int fs_table_count(sqlite3 *db, const char *table, int *count)
{
    char sql[128];
    sqlite3_stmt *st = NULL;
    int rc = -1;

    if (!table || !count ||
        snprintf(sql, sizeof(sql), "SELECT COUNT(*) FROM %s", table) >= (int)sizeof(sql))
        return -1;
    if (fs_prepare(db, &st, sql) == 0 && sqlite3_step(st) == SQLITE_ROW) {
        *count = sqlite3_column_int(st, 0);
        rc = 0;
    }
    if (st)
        sqlite3_finalize(st);
    return rc;
}

static int fs_table_has_rows(sqlite3 *db, const char *table)
{
    sqlite3_stmt *st = NULL;
    char sql[160];
    int exists = 0;

    if (!table || snprintf(sql, sizeof(sql),
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1") >= (int)sizeof(sql) ||
        fs_prepare(db, &st, sql) != 0)
        return 0;
    sqlite3_bind_text(st, 1, table, -1, SQLITE_TRANSIENT);
    exists = sqlite3_step(st) == SQLITE_ROW;
    sqlite3_finalize(st);
    if (!exists || snprintf(sql, sizeof(sql), "SELECT 1 FROM %s LIMIT 1", table) >= (int)sizeof(sql) ||
        fs_prepare(db, &st, sql) != 0)
        return 0;
    exists = sqlite3_step(st) == SQLITE_ROW;
    sqlite3_finalize(st);
    return exists;
}

static void fs_nfs_defaults_read(sqlite3 *db, struct json_object *data);

static int fs_schema_create(sqlite3 *db)
{
    static const char schema[] =
        "CREATE TABLE IF NOT EXISTS file_service_meta("
        "id INTEGER PRIMARY KEY CHECK(id=1),"
        "schema_version INTEGER NOT NULL,"
        "authority TEXT NOT NULL DEFAULT 'config_db',"
        "uci_migrated INTEGER NOT NULL DEFAULT 0,"
        "migration_state TEXT NOT NULL DEFAULT 'pending',"
        "revision INTEGER NOT NULL DEFAULT 0,"
        "last_error TEXT NOT NULL DEFAULT '',"
        "updated_at INTEGER NOT NULL);"
        "CREATE TABLE IF NOT EXISTS samba_service("
        "id INTEGER PRIMARY KEY CHECK(id=1),"
        "enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN(0,1)),"
        "workgroup TEXT NOT NULL DEFAULT 'WORKGROUP',"
        "server_description TEXT NOT NULL DEFAULT 'DreamingWrt',"
        "interfaces_json TEXT NOT NULL DEFAULT '[\"lan\"]',"
        "min_protocol TEXT NOT NULL DEFAULT 'SMB2',"
        "max_protocol TEXT NOT NULL DEFAULT 'SMB3_11',"
        "guest_access INTEGER NOT NULL DEFAULT 0 CHECK(guest_access IN(0,1)),"
        "revision INTEGER NOT NULL DEFAULT 1,"
        "updated_at INTEGER NOT NULL);"
        "CREATE TABLE IF NOT EXISTS samba_service_policy(id INTEGER PRIMARY KEY CHECK(id=1));"
        "CREATE TABLE IF NOT EXISTS nfs_service_defaults(id INTEGER PRIMARY KEY CHECK(id=1),"
        "clients TEXT NOT NULL,options TEXT NOT NULL,revision INTEGER NOT NULL);"
        "INSERT OR IGNORE INTO nfs_service_defaults VALUES(1,'','ro,sync,root_squash,no_subtree_check',1);"
        "CREATE TABLE IF NOT EXISTS samba_share("
        "id TEXT PRIMARY KEY,"
        "name TEXT NOT NULL COLLATE NOCASE UNIQUE,"
        "path TEXT NOT NULL,"
        "enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN(0,1)),"
        "read_only INTEGER NOT NULL DEFAULT 0 CHECK(read_only IN(0,1)),"
        "browseable INTEGER NOT NULL DEFAULT 1 CHECK(browseable IN(0,1)),"
        "network_discovery INTEGER NOT NULL DEFAULT 1 CHECK(network_discovery IN(0,1)),"
        "guest_access INTEGER NOT NULL DEFAULT 0 CHECK(guest_access IN(0,1)),"
        "allowed_users_json TEXT NOT NULL DEFAULT '[]',"
        "note TEXT NOT NULL DEFAULT '',"
        "revision INTEGER NOT NULL DEFAULT 1,"
        "created_at INTEGER NOT NULL,"
        "updated_at INTEGER NOT NULL);"
        "CREATE TABLE IF NOT EXISTS samba_share_acl("
        "share_id TEXT PRIMARY KEY REFERENCES samba_share(id) ON DELETE CASCADE,"
        "read_only_users_json TEXT NOT NULL DEFAULT '[]');"
        "CREATE TABLE IF NOT EXISTS nfs_export("
        "id TEXT PRIMARY KEY,"
        "enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN(0,1)),"
        "path TEXT NOT NULL,"
        "clients TEXT NOT NULL,"
        "options TEXT NOT NULL,"
        "note TEXT NOT NULL DEFAULT '',"
        "revision INTEGER NOT NULL DEFAULT 1,"
        "created_at INTEGER NOT NULL,"
        "updated_at INTEGER NOT NULL,"
        "UNIQUE(path,clients));";
    sqlite3_stmt *st = NULL;
    int64_t now = fs_now_s();

    if (fs_sql_exec(db, schema) != 0)
        return -1;
    if (fs_prepare(db, &st,
            "INSERT OR IGNORE INTO file_service_meta"
            "(id,schema_version,authority,uci_migrated,migration_state,revision,last_error,updated_at)"
            " VALUES(1,?1,'config_db',0,'pending',0,'',?2)") != 0)
        return -1;
    /* Mark initialization complete only after every protocol schema and seed. */
    sqlite3_bind_int(st, 1, 0);
    sqlite3_bind_int64(st, 2, now);
    if (fs_step_done(st) != 0) {
        sqlite3_finalize(st);
        return -1;
    }
    sqlite3_finalize(st);
    st = NULL;
    if (fs_prepare(db, &st,
            "INSERT OR IGNORE INTO samba_service"
            "(id,enabled,workgroup,server_description,interfaces_json,min_protocol,max_protocol,"
            "guest_access,revision,updated_at)"
            " VALUES(1,1,'WORKGROUP','DreamingWrt','[\"lan\"]','SMB2','SMB3_11',0,1,?1)") != 0)
        return -1;
    sqlite3_bind_int64(st, 1, now);
    if (fs_step_done(st) != 0) {
        sqlite3_finalize(st);
        return -1;
    }
    sqlite3_finalize(st);
    return 0;
}

static int fs_text_ok(const char *value, size_t max_len, int required)
{
    size_t i, len;

    if (!value || !(len = strlen(value)))
        return !required;
    if (len > max_len)
        return 0;
    for (i = 0; i < len; i++)
        if ((unsigned char)value[i] < 0x20 || (unsigned char)value[i] == 0x7f)
            return 0;
    return 1;
}

static int fs_copy_checked(char *destination, size_t destination_len,
                           const char *source)
{
    size_t len;

    if (!destination || !destination_len || !source ||
        (len = strlen(source)) >= destination_len)
        return -1;
    memcpy(destination, source, len + 1);
    return 0;
}

static int fs_id_ok(const char *id)
{
    size_t i, len;

    if (!id || !(len = strlen(id)) || len > FS_MAX_ID)
        return 0;
    for (i = 0; i < len; i++)
        if (!isalnum((unsigned char)id[i]) && id[i] != '-' &&
            id[i] != '_' && id[i] != '.')
            return 0;
    return 1;
}

static int fs_samba_name_ok(const char *name)
{
    size_t i, len;

    if (!fs_text_ok(name, FS_MAX_NAME, 1))
        return 0;
    len = strlen(name);
    for (i = 0; i < len; i++)
        if (name[i] == '/' || name[i] == '\\' || name[i] == '[' ||
            name[i] == ']' || name[i] == ':' || name[i] == ';' ||
            name[i] == '"' || name[i] == '\'')
            return 0;
    return strcmp(name, ".") && strcmp(name, "..");
}

static int fs_path_has_dotdot(const char *path)
{
    const char *p = path;

    while (p && *p) {
        while (*p == '/')
            p++;
        if (p[0] == '.' && p[1] == '.' && (p[2] == '/' || p[2] == '\0'))
            return 1;
        p = strchr(p, '/');
    }
    return 0;
}

static int fs_path_prefix(const char *path, const char *prefix)
{
    size_t len = strlen(prefix);

    return !strncmp(path, prefix, len) &&
           (path[len] == '\0' || path[len] == '/');
}

static int fs_path_forbidden(const char *path)
{
    static const char *const denied[] = {
        "/proc", "/sys", "/dev", "/run", "/boot", "/etc", "/usr",
        "/bin", "/sbin", "/lib", "/lib64", "/remote-share"
    };
    size_t i;

    for (i = 0; i < sizeof(denied) / sizeof(denied[0]); i++)
        if (fs_path_prefix(path, denied[i]))
            return 1;
    return 0;
}

static int fs_migration_path_ok(const char *path, char *canonical, size_t canonical_len)
{
    char resolved[PATH_MAX];
    char parent[PATH_MAX];
    char *slash;

    if (!path || path[0] != '/' || strlen(path) > FS_MAX_PATH ||
        !fs_text_ok(path, FS_MAX_PATH, 1) || fs_path_has_dotdot(path) ||
        fs_path_forbidden(path))
        return 0;
    if (realpath(path, resolved)) {
        struct stat st;
        if (fs_path_forbidden(resolved) || stat(resolved, &st) != 0 ||
            !S_ISDIR(st.st_mode) || strlen(resolved) >= canonical_len)
            return 0;
        snprintf(canonical, canonical_len, "%s", resolved);
        return 1;
    }
    if (errno != ENOENT && errno != ENOTDIR)
        return 0;
    snprintf(parent, sizeof(parent), "%s", path);
    while ((slash = strrchr(parent, '/')) != NULL) {
        if (slash == parent)
            parent[1] = '\0';
        else
            *slash = '\0';
        if (realpath(parent, resolved)) {
            if (fs_path_forbidden(resolved) || strlen(path) >= canonical_len)
                return 0;
            snprintf(canonical, canonical_len, "%s", path);
            return 1;
        }
        if (slash == parent)
            break;
    }
    return 0;
}

static int fs_share_path_ok(const char *path, char *canonical, size_t canonical_len)
{
    char resolved[PATH_MAX];

    if (!path || path[0] != '/' || !strcmp(path, "/") || strlen(path) > FS_MAX_PATH ||
        !fs_text_ok(path, FS_MAX_PATH, 1) || fs_path_has_dotdot(path) ||
        fs_path_forbidden(path))
        return 0;
    if (realpath(path, resolved)) {
        struct stat st;
        if (!strcmp(resolved, "/") || fs_path_forbidden(resolved) || stat(resolved, &st) != 0 ||
            !S_ISDIR(st.st_mode) || strlen(resolved) >= canonical_len)
            return 0;
        if (fs_path_prefix(resolved, "/mnt") || fs_path_prefix(resolved, "/media")) {
            struct stat root;
            if (stat("/", &root) != 0 || root.st_dev == st.st_dev) return 0;
        }
        snprintf(canonical, canonical_len, "%s", resolved);
        return 1;
    }

    return 0;
}

/* Revoking an existing publication must still work after its disk disappears. */
static int fs_share_path_update_ok(const char *path, const char *previous,
                                   struct json_object *payload,
                                   char *canonical, size_t canonical_len)
{
    struct json_object *enabled = NULL;
    if (fs_share_path_ok(path, canonical, canonical_len)) return 1;
    if (path && previous && previous[0] && !strcmp(path, previous) &&
        json_object_object_get_ex(payload, "enabled", &enabled) &&
        json_object_is_type(enabled, json_type_boolean) &&
        !json_object_get_boolean(enabled) && strlen(previous) < canonical_len) {
        snprintf(canonical, canonical_len, "%s", previous);
        return 1;
    }
    return 0;
}

static struct json_object *fs_payload(struct json_object *req)
{
    struct json_object *data = NULL;

    if (req && json_object_is_type(req, json_type_object) &&
        json_object_object_get_ex(req, "data", &data) && data &&
        json_object_is_type(data, json_type_object))
        return data;
    return req;
}

static int fs_confirmed(struct json_object *req)
{
    struct json_object *value = NULL;

    req = fs_payload(req);
    return req && json_object_is_type(req, json_type_object) &&
           json_object_object_get_ex(req, "confirm", &value) && value &&
           json_object_is_type(value, json_type_boolean) &&
           json_object_get_boolean(value);
}

static int fs_json_string(struct json_object *req, const char *key,
                          const char **value, int *present)
{
    struct json_object *item = NULL;

    *present = req && json_object_object_get_ex(req, key, &item);
    if (!*present)
        return 0;
    if (!item || !json_object_is_type(item, json_type_string))
        return -1;
    *value = json_object_get_string(item);
    return *value && strlen(*value) == (size_t)json_object_get_string_len(item) ? 0 : -1;
}

static int fs_json_bool(struct json_object *req, const char *key,
                        int *value, int *present)
{
    struct json_object *item = NULL;

    *present = req && json_object_object_get_ex(req, key, &item);
    if (!*present)
        return 0;
    if (!item || !json_object_is_type(item, json_type_boolean))
        return -1;
    *value = json_object_get_boolean(item);
    return 0;
}

static int fs_json_positive_int64(struct json_object *req, const char *key,
                                  int64_t *value, int *present)
{
    struct json_object *item = NULL;

    *present = req && json_object_object_get_ex(req, key, &item);
    if (!*present)
        return 0;
    if (!item || !json_object_is_type(item, json_type_int))
        return -1;
    *value = json_object_get_int64(item);
    return *value > 0 && *value < INT64_MAX ? 0 : -1;
}

static int fs_username_ok(const char *username)
{
    size_t i, len;

    if (!username || !(len = strlen(username)) || len > 64)
        return 0;
    for (i = 0; i < len; i++)
        if (!isalnum((unsigned char)username[i]) && username[i] != '_' &&
            username[i] != '-' && username[i] != '.')
            return 0;
    return getpwnam(username) != NULL;
}

static int fs_allowed_users_json(struct json_object *req, char **out, int *present)
{
    struct json_object *array = NULL;
    struct json_object *copy;
    size_t i, j, count;
    const char *text;

    *out = NULL;
    *present = req && json_object_object_get_ex(req, "allowed_users", &array);
    if (!*present)
        return 0;
    if (!array || !json_object_is_type(array, json_type_array) ||
        (count = json_object_array_length(array)) > FS_MAX_USERS)
        return -1;
    copy = json_object_new_array();
    if (!copy)
        return -1;
    for (i = 0; i < count; i++) {
        struct json_object *item = json_object_array_get_idx(array, i);
        const char *username;

        if (!item || !json_object_is_type(item, json_type_string) ||
            !(username = json_object_get_string(item)) || !fs_username_ok(username)) {
            json_object_put(copy);
            return -1;
        }
        for (j = 0; j < i; j++) {
            struct json_object *old = json_object_array_get_idx(copy, j);
            if (old && !strcmp(username, json_object_get_string(old))) {
                json_object_put(copy);
                return -1;
            }
        }
        json_object_array_add(copy, json_object_new_string(username));
    }
    text = json_object_to_json_string_ext(copy, JSON_C_TO_STRING_PLAIN);
    *out = text ? strdup(text) : NULL;
    json_object_put(copy);
    return *out ? 0 : -1;
}

static int fs_buffer_reserve(struct fs_buffer *buffer, size_t extra)
{
    size_t needed, capacity;
    char *next;

    if (!buffer || extra > FS_CONFIG_MAX || buffer->len > FS_CONFIG_MAX - extra)
        return -1;
    needed = buffer->len + extra + 1;
    if (needed <= buffer->cap)
        return 0;
    capacity = buffer->cap ? buffer->cap : 1024;
    while (capacity < needed) {
        if (capacity > FS_CONFIG_MAX / 2) {
            capacity = FS_CONFIG_MAX + 1;
            break;
        }
        capacity *= 2;
    }
    if (capacity > FS_CONFIG_MAX + 1)
        return -1;
    next = realloc(buffer->data, capacity);
    if (!next)
        return -1;
    buffer->data = next;
    buffer->cap = capacity;
    if (!buffer->len)
        buffer->data[0] = '\0';
    return 0;
}

static int fs_buffer_append_n(struct fs_buffer *buffer, const char *text, size_t len)
{
    if (!text || fs_buffer_reserve(buffer, len) != 0)
        return -1;
    memcpy(buffer->data + buffer->len, text, len);
    buffer->len += len;
    buffer->data[buffer->len] = '\0';
    return 0;
}

static int fs_buffer_append(struct fs_buffer *buffer, const char *text)
{
    return fs_buffer_append_n(buffer, text, text ? strlen(text) : 0);
}

static int fs_buffer_printf(struct fs_buffer *buffer, const char *format, ...)
{
    va_list args, copy;
    int needed;

    va_start(args, format);
    va_copy(copy, args);
    needed = vsnprintf(NULL, 0, format, copy);
    va_end(copy);
    if (needed < 0 || fs_buffer_reserve(buffer, (size_t)needed) != 0) {
        va_end(args);
        return -1;
    }
    vsnprintf(buffer->data + buffer->len, buffer->cap - buffer->len,
              format, args);
    va_end(args);
    buffer->len += (size_t)needed;
    return 0;
}

static int fs_buffer_uci_value(struct fs_buffer *buffer, const char *value)
{
    const unsigned char *p = (const unsigned char *)(value ? value : "");

    if (fs_buffer_append(buffer, "'") != 0)
        return -1;
    for (; *p; p++) {
        if (*p == '\'') {
            if (fs_buffer_append(buffer, "'\\''") != 0)
                return -1;
        } else if (*p < 0x20 || *p == 0x7f) {
            return -1;
        } else if (fs_buffer_append_n(buffer, (const char *)p, 1) != 0) {
            return -1;
        }
    }
    return fs_buffer_append(buffer, "'");
}

static void fs_buffer_free(struct fs_buffer *buffer)
{
    if (!buffer)
        return;
    free(buffer->data);
    memset(buffer, 0, sizeof(*buffer));
}

static int fs_wait_child(pid_t pid, int pipe_fd, int timeout_ms, char *output,
                         size_t output_len, struct fs_exec_result *result)
{
    int status = 0, child_done = 0;
    int64_t deadline, now;
    size_t used = 0;

    memset(result, 0, sizeof(*result));
    result->exit_code = 128;
    now = fs_monotonic_ms();
    if (now < 0) {
        kill(pid, SIGTERM);
        usleep(200000);
        if (waitpid(pid, &status, WNOHANG) == 0)
            kill(pid, SIGKILL);
        while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
        return -1;
    }
    deadline = now + timeout_ms;
    while (!child_done) {
        struct pollfd pfd = { .fd = pipe_fd, .events = POLLIN | POLLHUP };
        int wait_ms = 50;
        ssize_t got;

        now = fs_monotonic_ms();
        if (now < 0) {
            kill(pid, SIGTERM);
            usleep(200000);
            if (waitpid(pid, &status, WNOHANG) == 0)
                kill(pid, SIGKILL);
            while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
            break;
        }
        if (timeout_ms > 0 && now >= deadline) {
            result->timed_out = 1;
            kill(pid, SIGTERM);
            usleep(200000);
            if (waitpid(pid, &status, WNOHANG) == 0)
                kill(pid, SIGKILL);
            while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
            break;
        }
        if (timeout_ms > 0 && deadline - now < wait_ms)
            wait_ms = (int)(deadline - now);
        (void)poll(&pfd, 1, wait_ms);
        while ((got = read(pipe_fd,
                           output && used + 1 < output_len ? output + used :
                           (char [512]){0},
                           output && used + 1 < output_len ? output_len - used - 1 : 512)) > 0) {
            if (output && used + 1 < output_len)
                used += (size_t)got;
            else
                result->output_truncated = 1;
        }
        if (waitpid(pid, &status, WNOHANG) == pid)
            child_done = 1;
    }
    while (!result->timed_out) {
        char discard[512];
        char *dst = output && used + 1 < output_len ? output + used : discard;
        size_t room = output && used + 1 < output_len ? output_len - used - 1 : sizeof(discard);
        ssize_t got = read(pipe_fd, dst, room);
        if (got <= 0)
            break;
        if (dst == discard)
            result->output_truncated = 1;
        else
            used += (size_t)got;
    }
    if (output && output_len)
        output[used] = '\0';
    if (result->timed_out) {
        result->exit_code = 124;
        return -2;
    }
    if (WIFEXITED(status))
        result->exit_code = WEXITSTATUS(status);
    else if (WIFSIGNALED(status))
        result->exit_code = 128 + WTERMSIG(status);
    return result->exit_code == 0 ? 0 : -1;
}

static int fs_exec_argv(char *const argv[], int timeout_ms, char *output,
                        size_t output_len, struct fs_exec_result *result)
{
    int pipefd[2];
    pid_t pid;
    int flags, rc;

    if (!argv || !argv[0] || argv[0][0] != '/' || !result || pipe(pipefd) != 0)
        return -1;
    if (fcntl(pipefd[0], F_SETFD, FD_CLOEXEC) != 0 ||
        fcntl(pipefd[1], F_SETFD, FD_CLOEXEC) != 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }
    pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }
    if (pid == 0) {
        int nullfd = open("/dev/null", O_RDONLY | O_CLOEXEC);

        if (nullfd >= 0) {
            dup2(nullfd, STDIN_FILENO);
            close(nullfd);
        }
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[0]);
        close(pipefd[1]);
        clearenv();
        setenv("PATH", "/usr/sbin:/usr/bin:/sbin:/bin", 1);
        setenv("LANG", "C", 1);
        setenv("LC_ALL", "C", 1);
        execv(argv[0], argv);
        _exit(127);
    }
    close(pipefd[1]);
    flags = fcntl(pipefd[0], F_GETFL, 0);
    if (flags >= 0)
        (void)fcntl(pipefd[0], F_SETFL, flags | O_NONBLOCK);
    rc = fs_wait_child(pid, pipefd[0], timeout_ms, output, output_len, result);
    close(pipefd[0]);
    return rc;
}

static int fs_service_action(const char *script, const char *action,
                             struct fs_exec_result *result)
{
    char output[FS_SERVICE_OUTPUT_MAX];
    char *argv[3];
    int rc;

    if (!script || !action || access(script, X_OK) != 0) {
        memset(result, 0, sizeof(*result));
        result->exit_code = 127;
        return -1;
    }
    argv[0] = (char *)script;
    argv[1] = (char *)action;
    argv[2] = NULL;
    rc = fs_exec_argv(argv, FS_SERVICE_TIMEOUT_MS, output, sizeof(output), result);
    if (rc == 0 && (strstr(output, "Syntax:") || strstr(output, "Usage:") ||
                    strstr(output, "Available commands:"))) {
        result->exit_code = 64;
        return -1;
    }
    return rc;
}

static int fs_service_running(const char *script)
{
    struct fs_exec_result result;

    return access(script, X_OK) == 0 &&
           fs_service_action(script, "status", &result) == 0;
}

static int fs_config_preflight(const char *package, const char *rendered,
                               size_t rendered_len)
{
    char directory[] = "/tmp/dreamingwrt-fs-uci.XXXXXX";
    char path[PATH_MAX] = {0};
    struct uci_context *context = NULL;
    struct uci_package *config = NULL;
    int fd = -1, rc = -1;

    if (!package || !rendered || !mkdtemp(directory) ||
        snprintf(path, sizeof(path), "%s/%s", directory, package) >= (int)sizeof(path))
        goto out;
    fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0 || fs_write_all(fd, rendered, rendered_len) != 0 ||
        fsync(fd) != 0 || close(fd) != 0)
        goto out;
    fd = -1;
    context = uci_alloc_context();
    if (!context)
        goto out;
    uci_set_confdir(context, directory);
    if (uci_load(context, package, &config) != UCI_OK || !config)
        goto out;
    rc = 0;
out:
    if (config && context)
        uci_unload(context, config);
    if (context)
        uci_free_context(context);
    if (fd >= 0)
        close(fd);
    if (path[0])
        unlink(path);
    if (directory[0])
        rmdir(directory);
    return rc;
}

static int fs_binary_present(const char *const paths[])
{
    size_t i;

    for (i = 0; paths && paths[i]; i++)
        if (access(paths[i], X_OK) == 0)
            return 1;
    return 0;
}

static int fs_write_all(int fd, const void *data, size_t len)
{
    const unsigned char *p = data;

    while (len) {
        ssize_t written = write(fd, p, len);
        if (written < 0 && errno == EINTR)
            continue;
        if (written <= 0)
            return -1;
        p += written;
        len -= (size_t)written;
    }
    return 0;
}

static int fs_parent_fsync(const char *path)
{
    char parent[PATH_MAX];
    char *slash;
    int fd, rc;

    if (!path || strlen(path) >= sizeof(parent))
        return -1;
    snprintf(parent, sizeof(parent), "%s", path);
    slash = strrchr(parent, '/');
    if (!slash)
        return -1;
    if (slash == parent)
        parent[1] = '\0';
    else
        *slash = '\0';
    fd = open(parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    rc = fsync(fd);
    close(fd);
    return rc;
}

static int fs_snapshot_read(const char *path, struct fs_snapshot *snapshot)
{
    struct stat st;
    int fd;
    size_t used = 0;

    memset(snapshot, 0, sizeof(*snapshot));
    if (lstat(path, &st) != 0)
        return errno == ENOENT ? 0 : -1;
    if (!S_ISREG(st.st_mode) || st.st_size < 0 || (uint64_t)st.st_size > FS_CONFIG_MAX)
        return -1;
    snapshot->data = malloc((size_t)st.st_size + 1);
    if (!snapshot->data)
        return -1;
    fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        goto failed;
    while (used < (size_t)st.st_size) {
        ssize_t got = read(fd, snapshot->data + used, (size_t)st.st_size - used);
        if (got < 0 && errno == EINTR)
            continue;
        if (got <= 0) {
            close(fd);
            goto failed;
        }
        used += (size_t)got;
    }
    close(fd);
    snapshot->data[used] = '\0';
    snapshot->len = used;
    snapshot->mode = st.st_mode & 0777;
    snapshot->existed = 1;
    return 0;
failed:
    free(snapshot->data);
    memset(snapshot, 0, sizeof(*snapshot));
    return -1;
}

static void fs_snapshot_free(struct fs_snapshot *snapshot)
{
    if (!snapshot)
        return;
    free(snapshot->data);
    memset(snapshot, 0, sizeof(*snapshot));
}

static int fs_atomic_replace(const char *path, const char *data, size_t len,
                             mode_t mode)
{
    char tmp[PATH_MAX];
    int fd = -1, rc = -1;

    if (!path || !data || strlen(path) + 48 >= sizeof(tmp))
        return -1;
    snprintf(tmp, sizeof(tmp), "%s.tmp.%ld.%lld", path, (long)getpid(),
             (long long)fs_now_s());
    fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, mode);
    if (fd < 0)
        return -1;
    if (fs_write_all(fd, data, len) != 0 || fsync(fd) != 0 || close(fd) != 0) {
        fd = -1;
        goto out;
    }
    fd = -1;
    if (rename(tmp, path) != 0 || fs_parent_fsync(path) != 0)
        goto out;
    rc = 0;
out:
    if (fd >= 0)
        close(fd);
    if (rc != 0)
        unlink(tmp);
    return rc;
}

static int fs_snapshot_restore(const char *path, const struct fs_snapshot *snapshot)
{
    if (snapshot->existed)
        return fs_atomic_replace(path, snapshot->data, snapshot->len,
                                 snapshot->mode ? snapshot->mode : 0600);
    if (unlink(path) != 0 && errno != ENOENT)
        return -1;
    return fs_parent_fsync(path);
}

static int fs_bool_text(const char *value, int fallback)
{
    if (!value || !value[0])
        return fallback;
    if (!strcasecmp(value, "1") || !strcasecmp(value, "yes") ||
        !strcasecmp(value, "true") || !strcasecmp(value, "on"))
        return 1;
    if (!strcasecmp(value, "0") || !strcasecmp(value, "no") ||
        !strcasecmp(value, "false") || !strcasecmp(value, "off"))
        return 0;
    return fallback;
}

static char *fs_trim(char *text)
{
    char *end;

    while (*text && isspace((unsigned char)*text))
        text++;
    end = text + strlen(text);
    while (end > text && isspace((unsigned char)end[-1]))
        *--end = '\0';
    return text;
}

static int fs_uci_token(char **cursor, char *out, size_t out_len)
{
    char *p = fs_trim(*cursor);
    char quote = 0;
    size_t used = 0;

    if (!*p || *p == '#')
        return 0;
    if (*p == '\'' || *p == '"')
        quote = *p++;
    while (*p) {
        if (quote) {
            if (*p == quote) {
                p++;
                break;
            }
        } else if (isspace((unsigned char)*p) || *p == '#') {
            break;
        }
        if (*p == '\\' && p[1])
            p++;
        if (used + 1 >= out_len || (unsigned char)*p < 0x20)
            return -1;
        out[used++] = *p++;
    }
    out[used] = '\0';
    *cursor = p;
    return used ? 1 : 0;
}

static int fs_uci_read(const char *path, char **text_out)
{
    struct fs_snapshot snapshot;

    *text_out = NULL;
    if (fs_snapshot_read(path, &snapshot) != 0)
        return -1;
    if (!snapshot.existed)
        return 0;
    *text_out = snapshot.data;
    snapshot.data = NULL;
    fs_snapshot_free(&snapshot);
    return 0;
}

static int fs_migration_insert_samba_service(sqlite3 *db, const char *workgroup,
                                              const char *description,
                                              const char *interface)
{
    sqlite3_stmt *st = NULL;
    struct json_object *interfaces = json_object_new_array();
    const char *json;
    int rc = -1;

    if (!interfaces)
        return -1;
    if (interface && interface[0]) {
        char copy[257], *save = NULL, *item;
        snprintf(copy, sizeof(copy), "%s", interface);
        for (item = strtok_r(copy, " ,\t", &save); item;
             item = strtok_r(NULL, " ,\t", &save))
            if (fs_id_ok(item))
                json_object_array_add(interfaces, json_object_new_string(item));
    }
    if (!json_object_array_length(interfaces))
        json_object_array_add(interfaces, json_object_new_string("lan"));
    json = json_object_to_json_string_ext(interfaces, JSON_C_TO_STRING_PLAIN);
    if (fs_prepare(db, &st,
            "UPDATE samba_service SET workgroup=?1,server_description=?2,interfaces_json=?3,"
            "revision=revision+1,updated_at=?4 WHERE id=1") == 0) {
        sqlite3_bind_text(st, 1, workgroup && workgroup[0] ? workgroup : "WORKGROUP",
                          -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, description && description[0] ? description : "DreamingWrt",
                          -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 3, json, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 4, fs_now_s());
        rc = fs_step_done(st);
    }
    if (st)
        sqlite3_finalize(st);
    json_object_put(interfaces);
    return rc;
}

static int fs_migration_insert_samba_share(sqlite3 *db, int ordinal,
                                            const char *name, const char *path,
                                            const char *users, int enabled,
                                            int read_only, int browseable,
                                            int guest_access)
{
    char id[FS_MAX_ID + 1];
    char canonical[FS_MAX_PATH + 1];
    struct json_object *array = json_object_new_array();
    sqlite3_stmt *st = NULL;
    char user_copy[1025], *save = NULL, *user;
    const char *json;
    int rc = -1;

    if (!array || !fs_samba_name_ok(name) ||
        !fs_migration_path_ok(path, canonical, sizeof(canonical)))
        goto out;
    if (users && users[0]) {
        snprintf(user_copy, sizeof(user_copy), "%s", users);
        for (user = strtok_r(user_copy, " ,\t", &save); user;
             user = strtok_r(NULL, " ,\t", &save)) {
            if (!fs_username_ok(user))
                goto out;
            json_object_array_add(array, json_object_new_string(user));
        }
    }
    snprintf(id, sizeof(id), "samba-migrated-%d", ordinal);
    json = json_object_to_json_string_ext(array, JSON_C_TO_STRING_PLAIN);
    if (fs_prepare(db, &st,
            "INSERT OR IGNORE INTO samba_share"
            "(id,name,path,enabled,read_only,browseable,network_discovery,guest_access,"
            "allowed_users_json,note,revision,created_at,updated_at)"
            " VALUES(?1,?2,?3,?4,?5,?6,?6,?7,?8,'migrated_from_uci',1,?9,?9)") != 0)
        goto out;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, canonical, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 4, enabled);
    sqlite3_bind_int(st, 5, read_only);
    sqlite3_bind_int(st, 6, browseable);
    sqlite3_bind_int(st, 7, guest_access);
    sqlite3_bind_text(st, 8, json, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 9, fs_now_s());
    rc = fs_step_done(st);
out:
    if (st)
        sqlite3_finalize(st);
    if (array)
        json_object_put(array);
    return rc;
}

static int fs_migrate_samba(sqlite3 *db)
{
    char *text = NULL, *line, *save = NULL;
    char section[32] = "", name[FS_MAX_NAME + 1] = "";
    char path[FS_MAX_PATH + 1] = "", users[1025] = "";
    char workgroup[65] = "WORKGROUP", description[129] = "DreamingWrt";
    char interface[257] = "lan";
    int enabled = 1, read_only = 0, browseable = 1, guest = 0, ordinal = 0;
    int share_active = 0, rc = 0;

    if (fs_uci_read(JMX_SAMBA_CONFIG_PATH, &text) != 0)
        return -1;
    if (!text)
        return 0;
    for (line = strtok_r(text, "\n", &save); line;
         line = strtok_r(NULL, "\n", &save)) {
        char *cursor = line;
        char command[32], key[64], value[1025];
        int token = fs_uci_token(&cursor, command, sizeof(command));

        if (token <= 0)
            continue;
        if (!strcmp(command, "config")) {
            if (share_active && name[0] && path[0] &&
                fs_migration_insert_samba_share(db, ++ordinal, name, path, users,
                    enabled, read_only, browseable, guest) != 0)
                rc = -1;
            share_active = 0;
            name[0] = path[0] = users[0] = '\0';
            enabled = 1; read_only = 0; browseable = 1; guest = 0;
            if (fs_uci_token(&cursor, section, sizeof(section)) <= 0)
                section[0] = '\0';
            share_active = !strcmp(section, "sambashare");
            continue;
        }
        if (strcmp(command, "option") ||
            fs_uci_token(&cursor, key, sizeof(key)) <= 0 ||
            fs_uci_token(&cursor, value, sizeof(value)) <= 0)
            continue;
        if (!strcmp(section, "samba")) {
            if (!strcmp(key, "workgroup") && fs_text_ok(value, 64, 1))
                (void)fs_copy_checked(workgroup, sizeof(workgroup), value);
            else if (!strcmp(key, "description") && fs_text_ok(value, 128, 1))
                (void)fs_copy_checked(description, sizeof(description), value);
            else if (!strcmp(key, "interface") && fs_text_ok(value, 256, 1))
                (void)fs_copy_checked(interface, sizeof(interface), value);
        } else if (share_active) {
            if (!strcmp(key, "name")) (void)fs_copy_checked(name, sizeof(name), value);
            else if (!strcmp(key, "path")) (void)fs_copy_checked(path, sizeof(path), value);
            else if (!strcmp(key, "users")) (void)fs_copy_checked(users, sizeof(users), value);
            else if (!strcmp(key, "enabled")) enabled = fs_bool_text(value, 1);
            else if (!strcmp(key, "read_only")) read_only = fs_bool_text(value, 0);
            else if (!strcmp(key, "browseable")) browseable = fs_bool_text(value, 1);
            else if (!strcmp(key, "guest_ok")) guest = fs_bool_text(value, 0);
        }
    }
    if (share_active && name[0] && path[0] &&
        fs_migration_insert_samba_share(db, ++ordinal, name, path, users,
            enabled, read_only, browseable, guest) != 0)
        rc = -1;
    if (fs_migration_insert_samba_service(db, workgroup, description, interface) != 0)
        rc = -1;
    free(text);
    return rc;
}

static int fs_client_hostname_ok(const char *value)
{
    const char *p = value;
    size_t label = 0;

    if (!value || !value[0] || strlen(value) > 253)
        return 0;
    if (p[0] == '*' && p[1] == '.')
        p += 2;
    for (; *p; p++) {
        if (*p == '.') {
            if (!label || p[-1] == '-')
                return 0;
            label = 0;
            continue;
        }
        if (!isalnum((unsigned char)*p) && *p != '-')
            return 0;
        if (!label && *p == '-')
            return 0;
        if (++label > 63)
            return 0;
    }
    return label && p[-1] != '-';
}

static int fs_nfs_client_token_ok(const char *token)
{
    char copy[INET6_ADDRSTRLEN + 8];
    char *slash;
    unsigned char address[sizeof(struct in6_addr)];
    int family = AF_INET, bits, max_bits = 32;

    if (!strcmp(token, "*"))
        return 1;
    if (strlen(token) >= sizeof(copy))
        return fs_client_hostname_ok(token);
    snprintf(copy, sizeof(copy), "%s", token);
    slash = strrchr(copy, '/');
    if (slash) {
        char *end = NULL;
        long parsed;
        *slash++ = '\0';
        errno = 0;
        parsed = strtol(slash, &end, 10);
        if (errno || !end || *end)
            return 0;
        bits = (int)parsed;
    } else {
        bits = -1;
    }
    if (strchr(copy, ':')) {
        family = AF_INET6;
        max_bits = 128;
    }
    if (inet_pton(family, copy, address) == 1)
        return bits < 0 || (bits >= 0 && bits <= max_bits);
    return !slash && fs_client_hostname_ok(token);
}

static int fs_nfs_clients_ok(const char *clients)
{
    char copy[513], *save = NULL, *token;
    int count = 0;

    if (!fs_text_ok(clients, 512, 1))
        return 0;
    snprintf(copy, sizeof(copy), "%s", clients);
    for (token = strtok_r(copy, " ,\t", &save); token;
         token = strtok_r(NULL, " ,\t", &save)) {
        if (++count > 64 || !fs_nfs_client_token_ok(token))
            return 0;
    }
    return count > 0;
}

static int fs_uint_value(const char *text, unsigned long maximum)
{
    char *end = NULL;
    unsigned long value;

    if (!text || !text[0])
        return 0;
    errno = 0;
    value = strtoul(text, &end, 10);
    return !errno && end && !*end && value <= maximum;
}

static int fs_nfs_option_ok(const char *option)
{
    static const char *const flags[] = {
        "ro", "rw", "sync", "async", "wdelay", "no_wdelay",
        "root_squash", "no_root_squash", "all_squash", "no_all_squash",
        "subtree_check", "no_subtree_check", "secure", "insecure",
        "secure_locks", "insecure_locks", "hide", "nohide", "crossmnt",
        "no_crossmnt", "acl", "no_acl"
    };
    size_t i;

    for (i = 0; i < sizeof(flags) / sizeof(flags[0]); i++)
        if (!strcmp(option, flags[i]))
            return 1;
    if (!strncmp(option, "anonuid=", 8))
        return fs_uint_value(option + 8, UINT32_MAX);
    if (!strncmp(option, "anongid=", 8))
        return fs_uint_value(option + 8, UINT32_MAX);
    if (!strncmp(option, "fsid=", 5))
        return fs_uint_value(option + 5, UINT32_MAX) || !strcmp(option + 5, "root");
    if (!strncmp(option, "sec=", 4))
        return !strcmp(option + 4, "sys") || !strcmp(option + 4, "krb5") ||
               !strcmp(option + 4, "krb5i") || !strcmp(option + 4, "krb5p");
    return 0;
}

static int fs_nfs_options_ok(const char *options)
{
    char copy[1025], *save = NULL, *option;
    char seen[FS_MAX_NFS_OPTIONS][64];
    int count = 0, i;

    if (!fs_text_ok(options, 1024, 1) || strchr(options, ' ') || strchr(options, '\t'))
        return 0;
    snprintf(copy, sizeof(copy), "%s", options);
    for (option = strtok_r(copy, ",", &save); option;
         option = strtok_r(NULL, ",", &save)) {
        if (++count > FS_MAX_NFS_OPTIONS || strlen(option) >= sizeof(seen[0]) ||
            !fs_nfs_option_ok(option))
            return 0;
        for (i = 0; i < count - 1; i++)
            if (!strcmp(seen[i], option))
                return 0;
        snprintf(seen[count - 1], sizeof(seen[0]), "%s", option);
    }
    return count > 0;
}

static int fs_migration_insert_nfs(sqlite3 *db, int ordinal, int enabled,
                                    const char *path, const char *clients,
                                    const char *options)
{
    char id[FS_MAX_ID + 1], canonical[FS_MAX_PATH + 1];
    sqlite3_stmt *st = NULL;
    int rc = -1;

    if (!fs_migration_path_ok(path, canonical, sizeof(canonical)) ||
        !fs_nfs_clients_ok(clients) || !fs_nfs_options_ok(options))
        return -1;
    snprintf(id, sizeof(id), "nfs-migrated-%d", ordinal);
    if (fs_prepare(db, &st,
            "INSERT OR IGNORE INTO nfs_export"
            "(id,enabled,path,clients,options,note,revision,created_at,updated_at)"
            " VALUES(?1,?2,?3,?4,?5,'migrated_from_uci',1,?6,?6)") == 0) {
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 2, enabled);
        sqlite3_bind_text(st, 3, canonical, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 4, clients, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 5, options, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 6, fs_now_s());
        rc = fs_step_done(st);
    }
    if (st)
        sqlite3_finalize(st);
    return rc;
}

static int fs_migrate_nfs(sqlite3 *db)
{
    char *text = NULL, *line, *save = NULL;
    char section[32] = "", path[FS_MAX_PATH + 1] = "";
    char clients[513] = "", options[1025] = "";
    int active = 0, enabled = 1, ordinal = 0, rc = 0;

    if (fs_uci_read(JMX_NFS_CONFIG_PATH, &text) != 0)
        return -1;
    if (!text)
        return 0;
    for (line = strtok_r(text, "\n", &save); line;
         line = strtok_r(NULL, "\n", &save)) {
        char *cursor = line;
        char command[32], key[64], value[1025];

        if (fs_uci_token(&cursor, command, sizeof(command)) <= 0)
            continue;
        if (!strcmp(command, "config")) {
            if (active && path[0] && clients[0] && options[0] &&
                fs_migration_insert_nfs(db, ++ordinal, enabled, path, clients, options) != 0)
                rc = -1;
            active = 0; enabled = 1;
            path[0] = clients[0] = options[0] = '\0';
            if (fs_uci_token(&cursor, section, sizeof(section)) > 0)
                active = !strcmp(section, "share");
            continue;
        }
        if (!active || strcmp(command, "option") ||
            fs_uci_token(&cursor, key, sizeof(key)) <= 0 ||
            fs_uci_token(&cursor, value, sizeof(value)) <= 0)
            continue;
        if (!strcmp(key, "enabled")) enabled = fs_bool_text(value, 1);
        else if (!strcmp(key, "path")) (void)fs_copy_checked(path, sizeof(path), value);
        else if (!strcmp(key, "clients")) (void)fs_copy_checked(clients, sizeof(clients), value);
        else if (!strcmp(key, "options")) (void)fs_copy_checked(options, sizeof(options), value);
    }
    if (active && path[0] && clients[0] && options[0] &&
        fs_migration_insert_nfs(db, ++ordinal, enabled, path, clients, options) != 0)
        rc = -1;
    free(text);
    return rc;
}

static int fs_migrate_once(sqlite3 *db, int samba_preexisting,
                           int nfs_preexisting)
{
    sqlite3_stmt *st = NULL;
    int migrated = 0, samba_count = 0, nfs_count = 0, rc = -1;
    const char *state = "complete";

    if (fs_prepare(db, &st,
            "SELECT uci_migrated FROM file_service_meta WHERE id=1") != 0)
        return -1;
    if (sqlite3_step(st) == SQLITE_ROW)
        migrated = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    if (migrated)
        return 0;
    if (fs_sql_exec(db, "BEGIN IMMEDIATE") != 0)
        return -1;
    if (fs_table_count(db, "samba_share", &samba_count) != 0 ||
        fs_table_count(db, "nfs_export", &nfs_count) != 0)
        goto rollback;
    if (!samba_preexisting && !samba_count && fs_migrate_samba(db) != 0)
        state = "complete_with_rejected_legacy_entries";
    if (!nfs_preexisting && !nfs_count && fs_migrate_nfs(db) != 0)
        state = "complete_with_rejected_legacy_entries";
    st = NULL;
    if (fs_prepare(db, &st,
            "UPDATE file_service_meta SET uci_migrated=1,migration_state=?1,"
            "revision=revision+1,last_error='',updated_at=?2 WHERE id=1") != 0)
        goto rollback;
    sqlite3_bind_text(st, 1, state, -1, SQLITE_STATIC);
    sqlite3_bind_int64(st, 2, fs_now_s());
    if (fs_step_done(st) != 0) {
        sqlite3_finalize(st);
        goto rollback;
    }
    sqlite3_finalize(st);
    st = NULL;
    if (fs_sql_exec(db, "COMMIT") != 0)
        goto rollback;
    return 0;
rollback:
    if (st)
        sqlite3_finalize(st);
    (void)fs_sql_exec(db, "ROLLBACK");
    return rc;
}

static int fs_db_open(sqlite3 **db_out)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *st = NULL;
    int flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX;
    int samba_preexisting, nfs_preexisting, ready = 0;

    *db_out = NULL;
    if (sqlite3_open_v2(JMX_FILE_SERVICES_DB_PATH, &db, flags, NULL) != SQLITE_OK) {
        if (db)
            sqlite3_close(db);
        return -1;
    }
    sqlite3_busy_timeout(db, FS_DB_BUSY_TIMEOUT_MS);
    if (fs_sql_exec(db, "PRAGMA foreign_keys=ON") != 0)
        goto fail;
    /* A status read must not request a write lock while the binding watcher
     * applies protocol configuration. FS_SCHEMA_VERSION covers all schemas below. */
    if (fs_prepare(db, &st,
            "SELECT schema_version,uci_migrated FROM file_service_meta WHERE id=1") == 0) {
        ready = sqlite3_step(st) == SQLITE_ROW &&
                sqlite3_column_int(st, 0) >= FS_SCHEMA_VERSION &&
                sqlite3_column_int(st, 1);
        sqlite3_finalize(st);
    }
    if (ready) {
        if (fs_bindings_seed(db) != 0)
            goto fail;
        *db_out = db;
        return 0;
    }
    samba_preexisting = fs_table_has_rows(db, "samba_service") ||
                        fs_table_has_rows(db, "samba_share");
    nfs_preexisting = fs_table_has_rows(db, "nfs_export");
    if (fs_schema_create(db) != 0 || fs_accounts_schema(db) != 0 || fs_operations_schema(db) != 0 || fs_dav_schema(db) != 0 || fs_ftp_schema(db) != 0 || fs_bindings_schema(db) != 0 ||
        fs_migrate_once(db, samba_preexisting, nfs_preexisting) != 0 || fs_bindings_seed(db) != 0) {
        goto fail;
    }
    if (fs_prepare(db, &st, "UPDATE file_service_meta SET schema_version=?1 WHERE id=1") != 0)
        goto fail;
    sqlite3_bind_int(st, 1, FS_SCHEMA_VERSION);
    int rc = fs_step_done(st);
    sqlite3_finalize(st);
    if (rc != 0)
        goto fail;
    *db_out = db;
    return 0;
fail:
    sqlite3_close(db);
    return -1;
}

static int fs_random_id(sqlite3 *db, const char *prefix, const char *table,
                        char *id, size_t id_len)
{
    unsigned char raw[12];
    char sql[128];
    int fd, attempt;

    if (!db || !prefix || !table ||
        snprintf(sql, sizeof(sql), "SELECT 1 FROM %s WHERE id=?1", table) >= (int)sizeof(sql))
        return -1;
    fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    for (attempt = 0; attempt < 8; attempt++) {
        sqlite3_stmt *st = NULL;
        size_t used = 0;
        int exists = 1;

        while (used < sizeof(raw)) {
            ssize_t got = read(fd, raw + used, sizeof(raw) - used);
            if (got < 0 && errno == EINTR)
                continue;
            if (got <= 0) {
                close(fd);
                return -1;
            }
            used += (size_t)got;
        }
        if (snprintf(id, id_len,
                "%s-%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
                prefix, raw[0], raw[1], raw[2], raw[3], raw[4], raw[5],
                raw[6], raw[7], raw[8], raw[9], raw[10], raw[11]) >= (int)id_len)
            break;
        if (fs_prepare(db, &st, sql) == 0) {
            sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
            exists = sqlite3_step(st) == SQLITE_ROW;
        }
        if (st)
            sqlite3_finalize(st);
        if (!exists) {
            close(fd);
            return 0;
        }
    }
    close(fd);
    return -1;
}

static int fs_process_running(const char *const names[])
{
    DIR *dir;
    struct dirent *entry;
    int found = 0;

    dir = opendir("/proc");
    if (!dir)
        return 0;
    while (!found && (entry = readdir(dir)) != NULL) {
        char path[PATH_MAX], comm[128];
        FILE *fp;
        size_t i;

        if (!isdigit((unsigned char)entry->d_name[0]))
            continue;
        for (i = 1; entry->d_name[i]; i++)
            if (!isdigit((unsigned char)entry->d_name[i]))
                break;
        if (entry->d_name[i])
            continue;
        snprintf(path, sizeof(path), "/proc/%s/comm", entry->d_name);
        fp = fopen(path, "r");
        if (!fp)
            continue;
        if (fgets(comm, sizeof(comm), fp)) {
            comm[strcspn(comm, "\r\n")] = '\0';
            for (i = 0; names && names[i]; i++)
                if (!strcmp(comm, names[i])) {
                    found = 1;
                    break;
                }
        }
        fclose(fp);
    }
    closedir(dir);
    return found;
}

static struct json_object *fs_capabilities_all(void)
{
    struct json_object *all = json_object_new_object();
    struct json_object *samba = json_object_new_object();
    struct json_object *nfs = json_object_new_object();
    struct json_object *webdav = json_object_new_object();
    struct json_object *ftp = json_object_new_object();

    json_object_object_add(samba, "shares", json_object_new_boolean(1));
    json_object_object_add(samba, "conditional_write", json_object_new_boolean(1));
    json_object_object_add(samba, "expected_revision_required", json_object_new_boolean(1));
    json_object_object_add(samba, "config_preflight", json_object_new_boolean(1));
    json_object_object_add(samba, "runtime_probe", json_object_new_boolean(1));
    json_object_object_add(samba, "settings", json_object_new_boolean(1));
    json_object_object_add(nfs, "exports", json_object_new_boolean(1));
    json_object_object_add(nfs, "conditional_write", json_object_new_boolean(1));
    json_object_object_add(nfs, "expected_revision_required", json_object_new_boolean(1));
    json_object_object_add(nfs, "config_preflight", json_object_new_boolean(1));
    json_object_object_add(nfs, "runtime_probe", json_object_new_boolean(1));
    json_object_object_add(nfs, "settings", json_object_new_boolean(1));
    json_object_object_add(nfs, "mounts", json_object_new_boolean(0));
    json_object_object_add(webdav, "settings", json_object_new_boolean(0));
    json_object_object_add(webdav, "download_registry", json_object_new_boolean(0));
    const char *ftp_keys[]={"settings","shares","users","actions","autostart","tls"};
    for(size_t i=0;i<sizeof ftp_keys/sizeof ftp_keys[0];i++)json_object_object_add(ftp,ftp_keys[i],json_object_new_boolean(fs_ftp_installed()));
    json_object_object_add(all, "samba", samba);
    json_object_object_add(all, "nfs", nfs);
    json_object_object_add(all, "webdav", webdav);
    json_object_object_add(all, "ftp", ftp);
    return all;
}

static struct json_object *fs_capability_reasons_all(void)
{
    struct json_object *all = json_object_new_object();
    struct json_object *samba = json_object_new_object();
    struct json_object *nfs = json_object_new_object();
    struct json_object *webdav = json_object_new_object();
    struct json_object *ftp = json_object_new_object();

    json_object_object_add(nfs, "mounts",
                           json_object_new_string("nfs_mount_manager_pending"));
    json_object_object_add(webdav, "settings",
                           json_object_new_string("shared_nginx_transaction_and_acl_pending"));
    json_object_object_add(webdav, "download_registry",
                           json_object_new_string("shared_nginx_transaction_and_acl_pending"));
    if(!fs_ftp_installed()){
        const char *keys[]={"settings","shares","users","actions","autostart","tls"};
        for(size_t i=0;i<sizeof keys/sizeof keys[0];i++)json_object_object_add(ftp,keys[i],json_object_new_string("managed_ftp_runtime_missing"));
    }
    json_object_object_add(all, "samba", samba);
    json_object_object_add(all, "nfs", nfs);
    json_object_object_add(all, "webdav", webdav);
    json_object_object_add(all, "ftp", ftp);
    return all;
}

static void fs_add_contract(struct json_object *data)
{
    json_object_object_add(data, "contract_version",
                           json_object_new_string("file-services.v2"));
}

static struct json_object *fs_single_capabilities(const char *service)
{
    struct json_object *all = fs_capabilities_all();
    struct json_object *single = NULL;

    if (json_object_object_get_ex(all, service, &single) && single)
        json_object_get(single);
    json_object_put(all);
    return single ? single : json_object_new_object();
}

static struct json_object *fs_single_reasons(const char *service)
{
    struct json_object *all = fs_capability_reasons_all();
    struct json_object *single = NULL;

    if (json_object_object_get_ex(all, service, &single) && single)
        json_object_get(single);
    json_object_put(all);
    return single ? single : json_object_new_object();
}

static struct json_object *fs_json_array_text(const char *text)
{
    struct json_object *value = text ? json_tokener_parse(text) : NULL;

    if (!value || !json_object_is_type(value, json_type_array)) {
        if (value)
            json_object_put(value);
        return json_object_new_array();
    }
    return value;
}

static struct json_object *fs_samba_share_row(sqlite3 *db,sqlite3_stmt *st)
{
    struct json_object *item = json_object_new_object();

    json_object_object_add(item, "id", json_object_new_string(fs_sql_text(st, 0, "")));
    json_object_object_add(item, "name", json_object_new_string(fs_sql_text(st, 1, "")));
    json_object_object_add(item, "path", json_object_new_string(fs_sql_text(st, 2, "")));
    fs_binding_status(db,item,"samba",fs_sql_text(st,0,""),fs_sql_text(st,2,""));
    json_object_object_add(item, "enabled", json_object_new_boolean(sqlite3_column_int(st, 3)));
    json_object_object_add(item, "read_only", json_object_new_boolean(sqlite3_column_int(st, 4)));
    json_object_object_add(item, "browseable", json_object_new_boolean(sqlite3_column_int(st, 5)));
    json_object_object_add(item, "network_discovery",
                           json_object_new_boolean(sqlite3_column_int(st, 6)));
    json_object_object_add(item, "guest_access", json_object_new_boolean(sqlite3_column_int(st, 7)));
    json_object_object_add(item, "allowed_users",
                           fs_json_array_text(fs_sql_text(st, 8, "[]")));
    json_object_object_add(item, "read_only_users", fs_json_array_text(fs_sql_text(st, 13, "[]")));
    json_object_object_add(item, "note", json_object_new_string(fs_sql_text(st, 9, "")));
    json_object_object_add(item, "revision", json_object_new_int64(sqlite3_column_int64(st, 10)));
    json_object_object_add(item, "created_at",
                           json_object_new_int64(sqlite3_column_int64(st, 11)));
    json_object_object_add(item, "updated_at",
                           json_object_new_int64(sqlite3_column_int64(st, 12)));
    return item;
}

static struct json_object *fs_nfs_export_row(sqlite3 *db,sqlite3_stmt *st)
{
    struct json_object *item = json_object_new_object();

    json_object_object_add(item, "id", json_object_new_string(fs_sql_text(st, 0, "")));
    json_object_object_add(item, "enabled", json_object_new_boolean(sqlite3_column_int(st, 1)));
    json_object_object_add(item, "path", json_object_new_string(fs_sql_text(st, 2, "")));
    fs_binding_status(db,item,"nfs",fs_sql_text(st,0,""),fs_sql_text(st,2,""));
    json_object_object_add(item, "clients", json_object_new_string(fs_sql_text(st, 3, "")));
    json_object_object_add(item, "options", json_object_new_string(fs_sql_text(st, 4, "")));
    json_object_object_add(item, "note", json_object_new_string(fs_sql_text(st, 5, "")));
    json_object_object_add(item, "revision", json_object_new_int64(sqlite3_column_int64(st, 6)));
    json_object_object_add(item, "created_at",
                           json_object_new_int64(sqlite3_column_int64(st, 7)));
    json_object_object_add(item, "updated_at",
                           json_object_new_int64(sqlite3_column_int64(st, 8)));
    return item;
}

/* Runtime control belongs to the protocol daemon, not to SSH or global nginx. */
static const char *fs_control_script(const char *service)
{
    if (!strcmp(service, "samba")) return JMX_SAMBA_INIT_PATH;
    if (!strcmp(service, "nfs")) return JMX_NFSD_INIT_PATH;
    return NULL;
}

static int fs_control_running(const char *service)
{
    static const char *const smb[] = {"smbd", "samba", NULL};
    struct fs_exec_result result = {0};
    if (!strcmp(service, "samba"))
        return fs_service_running(JMX_SAMBA_INIT_PATH) || fs_process_running(smb);
    return fs_nfsd_threads_positive(&result);
}

static void fs_listeners_read(struct json_object *data, unsigned expected)
{
    /* Observed TCP listeners; absence is unknown when proc is unreadable. */
    struct json_object *listeners = json_object_new_array();
    const char *tables[] = {"/proc/net/tcp", "/proc/net/tcp6"};
    int read_tables = 0;
    for (size_t i = 0; i < 2; i++) {
        FILE *fp = fopen(tables[i], "r");
        char line[1024], address[65], remote[65];
        unsigned port, remote_port, state;
        if (!fp) continue;
        read_tables++;
        while (fgets(line, sizeof(line), fp)) {
            if (sscanf(line, " %*u: %64[0-9A-Fa-f]:%x %64[0-9A-Fa-f]:%x %x", address, &port, remote, &remote_port, &state) != 5 || port != expected || state != 10) continue;
            struct json_object *listener = json_object_new_object();
            char ip[INET6_ADDRSTRLEN];
            unsigned words[4] = {0};
            if (i == 0) sscanf(address, "%8x", &words[0]);
            else if (sscanf(address, "%8x%8x%8x%8x", &words[0], &words[1], &words[2], &words[3]) != 4) continue;
            if (!inet_ntop(i ? AF_INET6 : AF_INET, words, ip, sizeof(ip))) continue;
            json_object_object_add(listener, "address", json_object_new_string(ip));
            json_object_object_add(listener, "port", json_object_new_int(port));
            json_object_object_add(listener, "transport", json_object_new_string("tcp"));
            json_object_array_add(listeners, listener);
            /* A wildcard socket covers the host interface addresses, not a public reachability claim. */
            if (!strcmp(ip, "0.0.0.0") || !strcmp(ip, "::")) {
                struct ifaddrs *addresses = NULL;
                if (getifaddrs(&addresses) == 0) {
                    for (struct ifaddrs *ifa = addresses; ifa; ifa = ifa->ifa_next) {
                        if (!ifa->ifa_addr || (ifa->ifa_flags & IFF_LOOPBACK) || !(ifa->ifa_flags & IFF_UP) ||
                            ifa->ifa_addr->sa_family != (i ? AF_INET6 : AF_INET)) continue;
                        const void *addr = i ? (void *)&((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr :
                                              (void *)&((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;
                        if (i && IN6_IS_ADDR_LINKLOCAL((const struct in6_addr *)addr)) continue;
                        char target[INET6_ADDRSTRLEN];
                        if (!inet_ntop(i ? AF_INET6 : AF_INET, addr, target, sizeof(target))) continue;
                        struct json_object *candidate = json_object_new_object();
                        json_object_object_add(candidate, "address", json_object_new_string(target));
                        json_object_object_add(candidate, "port", json_object_new_int(port));
                        json_object_object_add(candidate, "transport", json_object_new_string("tcp"));
                        json_object_object_add(candidate, "source", json_object_new_string("wildcard_listener_interface"));
                        json_object_array_add(listeners, candidate);
                    }
                    freeifaddrs(addresses);
                }
            }

        }
        fclose(fp);
    }
    json_object_object_add(data, "listeners", listeners);
    json_object_object_add(data, "listeners_known", json_object_new_boolean(read_tables == 2));
}

static int fs_samba_extended_settings(void)
{
    char line[512]; FILE *fp = fopen(JMX_SAMBA_INIT_PATH, "r");
    if (!fp) return 0;
    int found = 0;
    while (fgets(line, sizeof(line), fp)) if (strstr(line, "dreamingwrt-samba-policy-v1")) { found = 1; break; }
    fclose(fp); return found;
}

static int fs_smb_protocol_rank(const char *name)
{
    const char *names[] = {"SMB2", "SMB2_02", "SMB2_10", "SMB3", "SMB3_00", "SMB3_02", "SMB3_11"};
    const int ranks[] = {0,0,1,2,2,3,4};
    for (int i=0; i<7; i++) if (!strcmp(name,names[i])) return ranks[i];
    return -1;
}

static void fs_control_read(sqlite3 *db, const char *service, struct json_object *data)
{
    const char *script = fs_control_script(service);
    struct fs_exec_result result = {0};
    sqlite3_stmt *st = NULL;
    struct json_object *available = NULL, *caps = NULL;
    int enabled_rc = script ? fs_service_action(script, "enabled", &result) : -1;
    json_object_object_get_ex(data, "available", &available);
    json_object_object_add(data, "installed", json_object_new_boolean(json_object_get_boolean(available)));
    json_object_object_add(data, "config_source", json_object_new_string("config_db"));
    json_object_object_add(data, "enabled", enabled_rc == 0 ? json_object_new_boolean(1) :
        result.exit_code == 1 ? json_object_new_boolean(0) : NULL);
    json_object_object_add(data, "enabled_source", json_object_new_string("init_symlink"));
    json_object_object_add(data, "running", json_object_new_boolean(fs_control_running(service)));
    json_object_object_get_ex(data, "capabilities", &caps);
    json_object_object_add(caps, "actions", json_object_new_boolean(json_object_get_boolean(available) && script && access(script, X_OK) == 0));
    json_object_object_add(caps, "autostart", json_object_new_boolean(json_object_get_boolean(available) && script && access(script, X_OK) == 0));
    if (!strcmp(service, "samba")) {
        struct json_object *fields = json_object_new_array();
        const char *names[] = {"workgroup", "server_description", "interfaces", "min_protocol", "max_protocol", "guest_access"};
        for (size_t i = 0; i < (fs_samba_extended_settings()?6:3); i++) json_object_array_add(fields, json_object_new_string(names[i]));
        json_object_object_add(data, "settings_fields", fields);
    }
    if (fs_prepare(db, &st, "SELECT revision,last_error FROM file_service_meta WHERE id=1") == 0 &&
        sqlite3_step(st) == SQLITE_ROW) {
        json_object_object_add(data, "control_revision", json_object_new_int64(sqlite3_column_int64(st, 0)));
        json_object_object_add(data, "last_error", json_object_new_string(fs_sql_text(st, 1, "")));
    }
    if (st) sqlite3_finalize(st);
    st=NULL;
    if(fs_prepare(db,&st,"SELECT error FROM file_share_binding_error WHERE service=?1")==0){
        sqlite3_bind_text(st,1,service,-1,SQLITE_STATIC);
        if(sqlite3_step(st)==SQLITE_ROW && fs_sql_text(st,0,"")[0])
            json_object_object_add(data,"last_error",json_object_new_string(fs_sql_text(st,0,"")));
    }
    if(st)sqlite3_finalize(st);
    fs_listeners_read(data, !strcmp(service, "samba") ? 445 : 2049);
}

static void fs_subjects_read(struct json_object *data)
{
    struct json_object *subjects = json_object_new_array();
    struct fs_exec_result result = {0};
    char output[FS_SERVICE_OUTPUT_MAX], *line, *save = NULL;
    char *argv[] = {(char *)JMX_SAMBA_PDBEDIT_PATH, (char *)"-L", NULL};
    int ok = access(argv[0], X_OK) == 0 && fs_exec_argv(argv, 3000, output, sizeof(output), &result) == 0 && !result.output_truncated;
    if (ok) for (line = strtok_r(output, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
        char *colon = strchr(line, ':');
        if (!colon) continue;
        *colon = '\0';
        struct passwd *pw = getpwnam(line);
        if (!pw || !fs_username_ok(line)) continue;
        struct json_object *item = json_object_new_object();
        json_object_object_add(item, "username", json_object_new_string(line));
        json_object_object_add(item, "system_uid", json_object_new_int64(pw->pw_uid));
        /* pdbedit -L proves membership, not password validity or account enabled state. */
        json_object_object_add(item, "credential_state", json_object_new_string("samba_account_present"));
        json_object_object_add(item, "has_password", NULL);
        json_object_array_add(subjects, item);
    }
    json_object_object_add(data, "subjects", subjects);
    json_object_object_add(data, "subjects_known", json_object_new_boolean(ok));
    json_object_object_add(data, "subjects_source", json_object_new_string("system_passwd+samba_passdb"));
}

static struct json_object *fs_samba_get_data(sqlite3 *db)
{
    static const char *const binaries[] = {
        "/usr/sbin/smbd", "/usr/sbin/samba", NULL
    };
    static const char *const processes[] = { "smbd", "samba", NULL };
    struct json_object *data = json_object_new_object();
    struct json_object *shares = json_object_new_array();
    struct json_object *interfaces = json_object_new_array();
    sqlite3_stmt *st = NULL;
    int available = access(JMX_SAMBA_INIT_PATH, X_OK) == 0 && fs_binary_present(binaries);
    int running = fs_service_running(JMX_SAMBA_INIT_PATH) || fs_process_running(processes);

    fs_add_contract(data);
    json_object_object_add(data, "service", json_object_new_string("samba"));
    json_object_object_add(data, "capabilities", fs_single_capabilities("samba"));
    json_object_object_add(data, "capability_reasons", fs_single_reasons("samba"));
    json_object_object_add(data, "available", json_object_new_boolean(available));
    json_object_object_add(data, "running", json_object_new_boolean(running));
    if (fs_prepare(db, &st,
            "SELECT enabled,workgroup,server_description,interfaces_json,min_protocol,"
            "max_protocol,CASE WHEN EXISTS(SELECT 1 FROM samba_service_policy) THEN guest_access ELSE 1 END,revision,updated_at FROM samba_service WHERE id=1") == 0 &&
        sqlite3_step(st) == SQLITE_ROW) {
        json_object_object_add(data, "enabled", json_object_new_boolean(sqlite3_column_int(st, 0)));
        json_object_object_add(data, "workgroup",
                               json_object_new_string(fs_sql_text(st, 1, "WORKGROUP")));
        json_object_object_add(data, "server_description",
                               json_object_new_string(fs_sql_text(st, 2, "DreamingWrt")));
        json_object_put(interfaces);
        interfaces = fs_json_array_text(fs_sql_text(st, 3, "[\"lan\"]"));
        json_object_object_add(data, "min_protocol",
                               json_object_new_string(fs_sql_text(st, 4, "SMB2")));
        json_object_object_add(data, "max_protocol",
                               json_object_new_string(fs_sql_text(st, 5, "SMB3_11")));
        json_object_object_add(data, "guest_access",
                               json_object_new_boolean(sqlite3_column_int(st, 6)));
        json_object_object_add(data, "revision", json_object_new_int(sqlite3_column_int(st, 7)));
        json_object_object_add(data, "updated_at",
                               json_object_new_int64(sqlite3_column_int64(st, 8)));
    } else {
        json_object_object_add(data, "enabled", json_object_new_boolean(1));
        json_object_object_add(data, "workgroup", json_object_new_string("WORKGROUP"));
        json_object_object_add(data, "server_description", json_object_new_string("DreamingWrt"));
        json_object_array_add(interfaces, json_object_new_string("lan"));
        json_object_object_add(data, "min_protocol", json_object_new_string("SMB2"));
        json_object_object_add(data, "max_protocol", json_object_new_string("SMB3_11"));
        json_object_object_add(data, "guest_access", json_object_new_boolean(0));
    }
    if (st)
        sqlite3_finalize(st);
    json_object_object_add(data, "interfaces", interfaces);
    st = NULL;
    if (fs_prepare(db, &st,
            "SELECT id,name,path,enabled,read_only,browseable,network_discovery,guest_access,"
            "allowed_users_json,note,revision,created_at,updated_at,"
            "COALESCE((SELECT read_only_users_json FROM samba_share_acl WHERE share_id=samba_share.id),'[]') FROM samba_share "
            "ORDER BY name COLLATE NOCASE,id") == 0)
        while (sqlite3_step(st) == SQLITE_ROW)
            json_object_array_add(shares, fs_samba_share_row(db,st));
    if (st)
        sqlite3_finalize(st);
    json_object_object_add(data, "shares", shares);
    json_object_object_add(data, "source", json_object_new_string("config_db"));
    fs_control_read(db, "samba", data);
    struct json_object *caps = NULL;
    json_object_object_get_ex(data, "capabilities", &caps);
    json_object_object_add(caps, "settings", json_object_new_boolean(available));
    json_object_object_add(data, "affected_shares", json_object_new_int(json_object_array_length(shares)));
    fs_subjects_read(data);
    return data;
}

static struct json_object *fs_nfs_get_data(sqlite3 *db)
{
    static const char *const binaries[] = {
        "/usr/sbin/exportfs", "/usr/sbin/rpc.mountd", "/usr/sbin/rpc.nfsd", NULL
    };
    static const char *const processes[] = { "rpc.mountd", "rpc.nfsd", "nfsd", NULL };
    struct json_object *data = json_object_new_object();
    struct json_object *exports = json_object_new_array();
    sqlite3_stmt *st = NULL;
    int available = access(JMX_NFS_INIT_PATH, X_OK) == 0 && fs_binary_present(binaries);
    int running = fs_service_running(JMX_NFS_INIT_PATH) || fs_process_running(processes);

    fs_add_contract(data);
    json_object_object_add(data, "service", json_object_new_string("nfs"));
    json_object_object_add(data, "capabilities", fs_single_capabilities("nfs"));
    json_object_object_add(data, "capability_reasons", fs_single_reasons("nfs"));
    json_object_object_add(data, "available", json_object_new_boolean(available));
    json_object_object_add(data, "running", json_object_new_boolean(running));
    if (fs_prepare(db, &st,
            "SELECT id,enabled,path,clients,options,note,revision,created_at,updated_at "
            "FROM nfs_export ORDER BY path,clients,id") == 0)
        while (sqlite3_step(st) == SQLITE_ROW)
            json_object_array_add(exports, fs_nfs_export_row(db,st));
    if (st)
        sqlite3_finalize(st);
    json_object_object_add(data, "exports", exports);
    json_object_object_add(data, "mounts", json_object_new_array());
    json_object_object_add(data, "source", json_object_new_string("config_db"));
    fs_control_read(db, "nfs", data);
    fs_nfs_defaults_read(db, data);
    return data;
}

/* Inspect the installed legacy configuration; never import its secret or claim it is managed. */
static void fs_webdav_config_read(struct json_object *data)
{
    struct uci_context *ctx = uci_alloc_context();
    struct uci_package *package = NULL;
    struct uci_element *element;
    if (!ctx) return;
    uci_set_confdir(ctx, JMX_WEBDAV_CONFIG_DIR);
    if (uci_load(ctx, "webdav", &package) != UCI_OK) { uci_free_context(ctx); return; }
    uci_foreach_element(&package->sections, element) {
        struct uci_section *section = uci_to_section(element);
        if (strcmp(section->e.name, "config")) continue;
        const char *strings[][2] = {{"username","username"},{"root_dir","root_dir"},{"cert_cer","cert_file"},{"cert_key","key_file"}};
        const char *booleans[][2] = {{"enable","configured_enabled"},{"read_only","read_only"},{"firewall_accept","open_firewall"},{"ssl","ssl"}};
        for (size_t i=0;i<sizeof(strings)/sizeof(strings[0]);i++) {
            const char *value=uci_lookup_option_string(ctx,section,strings[i][0]);
            if (value) json_object_object_add(data,strings[i][1],json_object_new_string(value));
        }
        for (size_t i=0;i<sizeof(booleans)/sizeof(booleans[0]);i++) {
            const char *value=uci_lookup_option_string(ctx,section,booleans[i][0]);
            json_object_object_add(data,booleans[i][1],json_object_new_boolean(fs_bool_text(value,0)));
        }
        const char *password=uci_lookup_option_string(ctx,section,"password");
        json_object_object_add(data,"has_password",json_object_new_boolean(password && *password));
        const char *port=uci_lookup_option_string(ctx,section,"listen_port");
        if (port && fs_uint_value(port,65535) && atoi(port)>0)
            json_object_object_add(data,"listen_port",json_object_new_int(atoi(port)));
        json_object_object_add(data,"source",json_object_new_string("legacy_uci_readonly"));
        json_object_object_add(data,"config_source",json_object_new_string("legacy_uci_readonly"));
        json_object_object_add(data,"managed",json_object_new_boolean(0));
        break;
    }
    uci_unload(ctx,package); uci_free_context(ctx);
}

static struct json_object *fs_webdav_get_data(void)
{
    struct json_object *data = json_object_new_object();
    int available = access("/etc/init.d/webdav", X_OK) == 0;

    fs_add_contract(data);
    json_object_object_add(data, "service", json_object_new_string("webdav"));
    json_object_object_add(data, "capabilities", fs_single_capabilities("webdav"));
    json_object_object_add(data, "capability_reasons", fs_single_reasons("webdav"));
    json_object_object_add(data, "available", json_object_new_boolean(available));
    json_object_object_add(data, "running", NULL);
    json_object_object_add(data, "runtime_reason", json_object_new_string("unmanaged_listener_not_probed"));
    json_object_object_add(data, "enabled", NULL);
    json_object_object_add(data, "listen_port", json_object_new_int(5005));
    json_object_object_add(data, "username", json_object_new_string(""));
    json_object_object_add(data, "has_password", json_object_new_boolean(0));
    json_object_object_add(data, "root_dir", json_object_new_string("/mnt"));
    json_object_object_add(data, "read_only", json_object_new_boolean(0));
    json_object_object_add(data, "open_firewall", json_object_new_boolean(0));
    json_object_object_add(data, "ssl", json_object_new_boolean(0));
    json_object_object_add(data, "cert_file", json_object_new_string(""));
    json_object_object_add(data, "key_file", json_object_new_string(""));
    json_object_object_add(data, "registry_download_available", json_object_new_boolean(0));
    json_object_object_add(data, "source", json_object_new_string("safe_defaults"));
    json_object_object_add(data, "installed", json_object_new_boolean(available));
    fs_webdav_config_read(data);
    struct json_object *port = NULL;
    json_object_object_get_ex(data, "listen_port", &port);
    fs_listeners_read(data, json_object_get_int(port));
    return data;
}


static int fs_meta_add(sqlite3 *db, struct json_object *data)
{
    sqlite3_stmt *st = NULL;
    int rc = -1;

    if (fs_prepare(db, &st,
            "SELECT schema_version,authority,uci_migrated,migration_state,revision,last_error,"
            "updated_at FROM file_service_meta WHERE id=1") == 0 &&
        sqlite3_step(st) == SQLITE_ROW) {
        struct json_object *meta = json_object_new_object();
        json_object_object_add(meta, "schema_version", json_object_new_int(sqlite3_column_int(st, 0)));
        json_object_object_add(meta, "authority",
                               json_object_new_string(fs_sql_text(st, 1, "config_db")));
        json_object_object_add(meta, "uci_migrated",
                               json_object_new_boolean(sqlite3_column_int(st, 2)));
        json_object_object_add(meta, "migration_state",
                               json_object_new_string(fs_sql_text(st, 3, "pending")));
        json_object_object_add(meta, "revision", json_object_new_int(sqlite3_column_int(st, 4)));
        json_object_object_add(meta, "last_error",
                               json_object_new_string(fs_sql_text(st, 5, "")));
        json_object_object_add(meta, "updated_at",
                               json_object_new_int64(sqlite3_column_int64(st, 6)));
        json_object_object_add(data, "meta", meta);
        rc = 0;
    }
    if (st)
        sqlite3_finalize(st);
    return rc;
}

/* Dependency inventory is separate from managed share capability. In
 * particular a working SSH daemon does not imply an isolated SFTP share. */
static struct json_object *fs_optional_service_data(const char *service)
{
    const char *const sftp_bins[] = {"/usr/lib/sftp-server", "/usr/libexec/sftp-server", NULL};
    const char *const dlna_bins[] = {"/usr/sbin/minidlnad", "/usr/bin/minidlna", "/usr/sbin/minidlna", NULL};
    const char *const afp_bins[] = {"/usr/sbin/afpd", "/usr/sbin/netatalk", NULL};
    const char *const sftp_processes[] = {"dropbear", "sshd", NULL};
    const char *const dlna_processes[] = {"minidlnad", "minidlna", NULL};
    const char *const afp_processes[] = {"afpd", "netatalk", NULL};
    int sftp = !strcmp(service, "sftp"), dlna = !strcmp(service, "dlna");
    int installed = fs_binary_present(sftp ? sftp_bins : dlna ? dlna_bins : afp_bins);
    int process = fs_process_running(sftp ? sftp_processes : dlna ? dlna_processes : afp_processes);
    struct json_object *data = json_object_new_object(), *caps = json_object_new_object();
    struct json_object *reasons = json_object_new_object();
    const char *reason = !installed ? "runtime_not_installed" : sftp ? "restricted_sftp_shares_pending" :
        dlna ? "media_directory_and_scan_manager_pending" : "afp_directory_and_acl_manager_pending";
    json_object_object_add(data, "service", json_object_new_string(service));
    json_object_object_add(data, "installed", json_object_new_boolean(installed));
    json_object_object_add(data, "available", json_object_new_boolean(installed));
    json_object_object_add(data, "dependency_running", json_object_new_boolean(process));
    json_object_object_add(data, "running", NULL);
    json_object_object_add(data, "enabled", NULL);
    json_object_object_add(data, "source", json_object_new_string("runtime_probe"));
    const char *names[] = {"settings", "shares", "actions", "autostart", "shared_access"};
    for (size_t i = 0; i < sizeof(names)/sizeof(names[0]); i++) {
        json_object_object_add(caps, names[i], json_object_new_boolean(0));
        json_object_object_add(reasons, names[i], json_object_new_string(reason));
    }
    json_object_object_add(data, "capabilities", caps);
    json_object_object_add(data, "capability_reasons", reasons);
    fs_add_contract(data);
    return data;
}

struct json_object *jmx_file_service_get(const char *service)
{
    sqlite3 *db = NULL;
    struct json_object *data;

    if (service && (!strcmp(service, "sftp") || !strcmp(service, "dlna") || !strcmp(service, "afp")))
        return fs_success(fs_optional_service_data(service));
    if (!service || (strcmp(service, "samba") && strcmp(service, "nfs") &&
        strcmp(service, "webdav") && strcmp(service, "ftp")))
        return fs_error("invalid_service", "supported_services_are_samba_nfs_webdav_ftp");
    if (fs_db_open(&db) != 0)
        return fs_error("storage_unavailable", "config_db_open_or_schema_failed");
    if (!strcmp(service, "samba"))
        data = fs_samba_get_data(db);
    else if (!strcmp(service, "nfs"))
        data = fs_nfs_get_data(db);
    else if (!strcmp(service, "webdav"))
        data = fs_dav_get(db);
    else
        data = fs_ftp_get(db);
    sqlite3_close(db);
    return fs_success(data);
}

struct json_object *jmx_file_services_get(void)
{
    sqlite3 *db = NULL;
    struct json_object *data;

    if (fs_db_open(&db) != 0)
        return fs_error("storage_unavailable", "config_db_open_or_schema_failed");
    data = json_object_new_object();
    fs_add_contract(data);
    json_object_object_add(data, "capabilities", fs_capabilities_all());
    json_object_object_add(data, "capability_reasons", fs_capability_reasons_all());
    json_object_object_add(data, "samba", fs_samba_get_data(db));
    json_object_object_add(data, "nfs", fs_nfs_get_data(db));
    json_object_object_add(data, "webdav", fs_dav_get(db));
    json_object_object_add(data, "ftp", fs_ftp_get(db));
    json_object_object_add(data, "accounts", fs_accounts_data(db));
    struct json_object *operations=json_object_new_object();
    json_object_object_add(operations,"manage",json_object_new_boolean(1));
    struct json_object *operation_info=json_object_new_object();
    json_object_object_add(operation_info,"capabilities",operations);
    json_object_object_add(data,"operations",operation_info);
    json_object_object_add(data, "sftp", fs_optional_service_data("sftp"));
    json_object_object_add(data, "dlna", fs_optional_service_data("dlna"));
    json_object_object_add(data, "afp", fs_optional_service_data("afp"));
    json_object_object_add(data, "generated_at", json_object_new_int64(fs_now_s()));
    (void)fs_meta_add(db, data);
    sqlite3_close(db);
    return fs_success(data);
}

static int fs_samba_users_value(struct fs_buffer *buffer, const char *json)
{
    struct json_object *array = fs_json_array_text(json);
    size_t i;
    int rc = 0;

    for (i = 0; i < json_object_array_length(array); i++) {
        struct json_object *item = json_object_array_get_idx(array, i);
        const char *username = item ? json_object_get_string(item) : NULL;
        if (!username || !fs_username_ok(username) ||
            (i && fs_buffer_append(buffer, " ") != 0) ||
            fs_buffer_append(buffer, username) != 0) {
            rc = -1;
            break;
        }
    }
    json_object_put(array);
    return rc;
}

static int fs_render_samba(sqlite3 *db, struct fs_buffer *buffer)
{
    sqlite3_stmt *st = NULL;
    struct json_object *interfaces = NULL;
    const char *workgroup = "WORKGROUP", *description = "DreamingWrt";
    size_t i;
    int rc = -1;

    if (fs_buffer_append(buffer,
            "# Generated by DreamingWrt from /etc/dreamingwrt/config.db.\n"
            "# Manual edits are replaced on the next successful apply.\n\n"
            "config samba\n") != 0)
        return -1;
    if (fs_prepare(db, &st,
            "SELECT workgroup,server_description,interfaces_json,min_protocol,max_protocol,"
            "CASE WHEN EXISTS(SELECT 1 FROM samba_service_policy) THEN guest_access ELSE 1 END "
            "FROM samba_service WHERE id=1") != 0 || sqlite3_step(st) != SQLITE_ROW)
        goto out;
    workgroup = fs_sql_text(st, 0, "WORKGROUP");
    description = fs_sql_text(st, 1, "DreamingWrt");
    interfaces = fs_json_array_text(fs_sql_text(st, 2, "[\"lan\"]"));
    if (fs_buffer_append(buffer, "\toption workgroup ") != 0 ||
        fs_buffer_uci_value(buffer, workgroup) != 0 ||
        fs_buffer_append(buffer, "\n\toption charset 'UTF-8'\n\toption description ") != 0 ||
        fs_buffer_uci_value(buffer, description) != 0 ||
        fs_buffer_append(buffer, "\n\toption interface ") != 0)
        goto out;
    {
        struct fs_buffer value = {0};
        for (i = 0; i < json_object_array_length(interfaces); i++) {
            const char *iface = json_object_get_string(json_object_array_get_idx(interfaces, i));
            if (!iface || !fs_id_ok(iface) ||
                (i && fs_buffer_append(&value, " ") != 0) ||
                fs_buffer_append(&value, iface) != 0) {
                fs_buffer_free(&value);
                goto out;
            }
        }
        if (!value.len && fs_buffer_append(&value, "lan") != 0) {
            fs_buffer_free(&value);
            goto out;
        }
        if (fs_buffer_uci_value(buffer, value.data) != 0) {
            fs_buffer_free(&value);
            goto out;
        }
        fs_buffer_free(&value);
    }
    if (fs_buffer_append(buffer,
            "\n\toption allow_legacy_protocols '0'\n\toption disable_netbios '1'\n") != 0)
        goto out;
    if (fs_samba_extended_settings() && fs_buffer_printf(buffer,
            "\toption dwrt_min_protocol '%s'\n\toption dwrt_max_protocol '%s'\n\toption dwrt_guest_access '%d'\n",
            fs_sql_text(st,3,"SMB2"),fs_sql_text(st,4,"SMB3_11"),sqlite3_column_int(st,5)) != 0) goto out;
    sqlite3_finalize(st);
    st = NULL;
    if (fs_prepare(db, &st,
            "SELECT name,path,read_only,browseable,network_discovery,guest_access,"
            "allowed_users_json,COALESCE((SELECT read_only_users_json FROM samba_share_acl WHERE share_id=samba_share.id),'[]'),id "
            "FROM samba_share WHERE enabled=1 ORDER BY name COLLATE NOCASE,id") != 0)
        goto out;
    while (sqlite3_step(st) == SQLITE_ROW) {
        const char *name = fs_sql_text(st, 0, "");
        const char *path = fs_sql_text(st, 1, "");
        const char *users = fs_sql_text(st, 6, "[]");
        int read_only = sqlite3_column_int(st, 2);
        int browseable = sqlite3_column_int(st, 3);
        int discovery = sqlite3_column_int(st, 4);
        int guest = sqlite3_column_int(st, 5);
        struct fs_buffer user_value = {0};
        char canonical[FS_MAX_PATH + 1];
        int bound=fs_binding_prepare(db,"samba",fs_sql_text(st,8,""),path,canonical,sizeof canonical);
        if(bound<0)goto out;
        if(!bound)continue;
        if (!fs_samba_name_ok(name) ||
            fs_samba_users_value(&user_value, users) != 0 ||
            fs_buffer_append(buffer, "\nconfig sambashare\n\toption name ") != 0 ||
            fs_buffer_uci_value(buffer, name) != 0 ||
            fs_buffer_append(buffer, "\n\toption path ") != 0 ||
            fs_buffer_uci_value(buffer, canonical) != 0 ||
            fs_buffer_printf(buffer,
                "\n\toption read_only '%s'\n\toption browseable '%s'\n"
                "\toption guest_ok '%s'\n",
                read_only ? "yes" : "no", (browseable && discovery) ? "yes" : "no",
                guest ? "yes" : "no") != 0) {
            fs_buffer_free(&user_value);
            goto out;
        }
        if (user_value.len &&
            (fs_buffer_append(buffer, "\toption users ") != 0 ||
             fs_buffer_uci_value(buffer, user_value.data) != 0 ||
             fs_buffer_append(buffer, "\n") != 0)) {
            fs_buffer_free(&user_value);
            goto out;
        }
        fs_buffer_free(&user_value);
        /* read list restricts users; never emit write list, which can override
         * the share-level read-only constraint. */
        struct fs_buffer readers = {0};
        if (fs_samba_users_value(&readers, fs_sql_text(st, 7, "[]")) != 0 ||
            (readers.len && (fs_buffer_append(buffer, "\toption read_list ") != 0 ||
             fs_buffer_uci_value(buffer, readers.data) != 0 || fs_buffer_append(buffer, "\n") != 0))) {
            fs_buffer_free(&readers); goto out;
        }
        fs_buffer_free(&readers);
    }
    rc = 0;
out:
    if (st)
        sqlite3_finalize(st);
    if (interfaces)
        json_object_put(interfaces);
    return rc;
}

static int fs_render_nfs(sqlite3 *db, struct fs_buffer *buffer)
{
    sqlite3_stmt *st = NULL;
    int rc = -1;

    if (fs_buffer_append(buffer,
            "# Generated by DreamingWrt from /etc/dreamingwrt/config.db.\n"
            "# Manual edits are replaced on the next successful apply.\n") != 0)
        return -1;
    if (fs_prepare(db, &st,
            "SELECT path,clients,options,id FROM nfs_export WHERE enabled=1 "
            "ORDER BY path,clients,id") != 0)
        return -1;
    while (sqlite3_step(st) == SQLITE_ROW) {
        const char *path = fs_sql_text(st, 0, "");
        const char *clients = fs_sql_text(st, 1, "");
        const char *options = fs_sql_text(st, 2, "");
        char canonical[FS_MAX_PATH + 1];

        int bound=fs_binding_prepare(db,"nfs",fs_sql_text(st,3,""),path,canonical,sizeof canonical);
        if(bound<0)goto out;
        if(!bound)continue;
        if (!fs_nfs_clients_ok(clients) || !fs_nfs_options_ok(options) ||
            fs_buffer_append(buffer, "\nconfig share\n\toption enabled '1'\n\toption path ") != 0 ||
            fs_buffer_uci_value(buffer, canonical) != 0 ||
            fs_buffer_append(buffer, "\n\toption clients ") != 0 ||
            fs_buffer_uci_value(buffer, clients) != 0 ||
            fs_buffer_append(buffer, "\n\toption options '") != 0 ||
            fs_buffer_append(buffer, options) != 0 ||
            fs_buffer_append(buffer, ",mountpoint'\n") != 0)
            goto out;
    }
    rc = 0;
out:
    if (st)
        sqlite3_finalize(st);
    return rc;
}

static int fs_render_nfs_exports(sqlite3 *db, struct fs_buffer *buffer)
{
    sqlite3_stmt *st = NULL;
    int count = 0;
    int rc = -1;

    if (fs_prepare(db, &st,
            "SELECT path,clients,options,id FROM nfs_export WHERE enabled=1 "
            "ORDER BY path,clients,id") != 0)
        goto out;
    while (sqlite3_step(st) == SQLITE_ROW) {
        const char *path = fs_sql_text(st, 0, "");
        const char *clients = fs_sql_text(st, 1, "");
        const char *options = fs_sql_text(st, 2, "");
        char client_copy[513], *save = NULL, *client;
        char canonical[FS_MAX_PATH + 1];

        int bound=fs_binding_prepare(db,"nfs",fs_sql_text(st,3,""),path,canonical,sizeof canonical);
        if(bound<0)goto out;
        if(!bound)continue;
        if ((!count && fs_buffer_append(buffer,
                "# Generated by DreamingWrt from /etc/dreamingwrt/config.db.\n") != 0) ||
            !fs_nfs_clients_ok(clients) || !fs_nfs_options_ok(options) ||
            fs_buffer_append(buffer, canonical) != 0)
            goto out;
        count++;
        snprintf(client_copy, sizeof(client_copy), "%s", clients);
        for (client = strtok_r(client_copy, " ,\t", &save); client;
             client = strtok_r(NULL, " ,\t", &save))
            if (fs_buffer_printf(buffer, "\t%s(%s,mountpoint)", client, options) != 0)
                goto out;
        if (fs_buffer_append(buffer, "\n") != 0)
            goto out;
    }
    if (!count && fs_buffer_append(buffer, "\n") != 0)
        goto out;
    rc = 0;
out:
    if (st)
        sqlite3_finalize(st);
    return rc;
}

static int fs_nfs_exports_apply(sqlite3 *db, struct fs_exec_result *result)
{
    struct fs_buffer rendered = {0};
    char output[FS_SERVICE_OUTPUT_MAX];
    char *unexport_argv[] = { (char *)JMX_NFS_EXPORTFS_PATH, (char *)"-ua", NULL };
    char *export_argv[] = { (char *)JMX_NFS_EXPORTFS_PATH, (char *)"-ra", NULL };
    int rc = -1;

    if (access(JMX_NFS_EXPORTFS_PATH, X_OK) != 0) {
        fs_probe_error(result, 127);
        return -1;
    }
    if (fs_render_nfs_exports(db, &rendered) != 0 ||
        fs_atomic_replace(JMX_NFS_NATIVE_CONFIG_PATH,
                          rendered.data ? rendered.data : "", rendered.len, 0644) != 0) {
        fs_probe_error(result, 74);
        goto out;
    }
    if (fs_exec_argv(unexport_argv, FS_SERVICE_TIMEOUT_MS, output,
                     sizeof(output), result) != 0 ||
        fs_exec_argv(export_argv, FS_SERVICE_TIMEOUT_MS, output,
                     sizeof(output), result) != 0)
        goto out;
    rc = 0;
out:
    fs_buffer_free(&rendered);
    return rc;
}

static void fs_probe_error(struct fs_exec_result *result, int exit_code)
{
    memset(result, 0, sizeof(*result));
    result->exit_code = exit_code;
}

static int fs_samba_runtime_probe(sqlite3 *db, struct fs_exec_result *result)
{
    sqlite3_stmt *st = NULL;
    char output[FS_SERVICE_OUTPUT_MAX];
    char *validate_argv[] = {
        (char *)JMX_SAMBA_TESTPARM_PATH, (char *)"-s",
        (char *)JMX_SAMBA_NATIVE_CONFIG_PATH, NULL
    };
    int rc = -1;

    if (fs_service_action(JMX_SAMBA_INIT_PATH, "status", result) != 0)
        return -1;
    if (access(JMX_SAMBA_TESTPARM_PATH, X_OK) != 0 ||
        access(JMX_SAMBA_NATIVE_CONFIG_PATH, R_OK) != 0) {
        fs_probe_error(result, 127);
        return -1;
    }
    if (fs_exec_argv(validate_argv, FS_SERVICE_TIMEOUT_MS, output,
                     sizeof(output), result) != 0 || result->output_truncated)
        return -1;
    if (fs_prepare(db, &st,
            "SELECT name,path,id FROM samba_share WHERE enabled=1 "
            "ORDER BY name COLLATE NOCASE,id") != 0) {
        fs_probe_error(result, 65);
        return -1;
    }
    while (sqlite3_step(st) == SQLITE_ROW) {
        const char *name = fs_sql_text(st, 0, "");
        const char *path = fs_sql_text(st, 1, "");
        char published[FS_MAX_PATH+1];
        if(!fs_binding_available(db,"samba",fs_sql_text(st,2,""),path))continue;
        if(fs_binding_prepare(db,"samba",fs_sql_text(st,2,""),path,published,sizeof published)!=1)goto out;
        path=published;
        char section_arg[FS_MAX_NAME + 32];
        char expected_path[FS_MAX_PATH + 16];
        char *section_argv[] = {
            (char *)JMX_SAMBA_TESTPARM_PATH, (char *)"-s", section_arg,
            (char *)JMX_SAMBA_NATIVE_CONFIG_PATH, NULL
        };

        if (snprintf(section_arg, sizeof(section_arg), "--section-name=%s", name) >=
                (int)sizeof(section_arg) ||
            snprintf(expected_path, sizeof(expected_path), "path = %s", path) >=
                (int)sizeof(expected_path) ||
            fs_exec_argv(section_argv, FS_SERVICE_TIMEOUT_MS, output,
                         sizeof(output), result) != 0 ||
            result->output_truncated || !strstr(output, expected_path)) {
            if (result->exit_code == 0)
                result->exit_code = 65;
            goto out;
        }
    }
    rc = 0;
out:
    sqlite3_finalize(st);
    return rc;
}

static int fs_nfsd_threads_positive(struct fs_exec_result *result)
{
    char value[64], *end = NULL;
    FILE *fp = fopen(JMX_NFSD_THREADS_PATH, "r");
    long threads;

    if (!fp || !fgets(value, sizeof(value), fp)) {
        if (fp)
            fclose(fp);
        fs_probe_error(result, 66);
        return 0;
    }
    fclose(fp);
    errno = 0;
    threads = strtol(value, &end, 10);
    while (end && isspace((unsigned char)*end))
        end++;
    if (errno || !end || *end || threads <= 0) {
        fs_probe_error(result, 66);
        return 0;
    }
    return 1;
}

static int fs_export_options_include(char *actual, const char *expected)
{
    char expected_copy[1025], *save = NULL, *option;

    if (!actual || !expected)
        return 0;
    snprintf(expected_copy, sizeof(expected_copy), "%s", expected);
    for (option = strtok_r(expected_copy, ",", &save); option;
         option = strtok_r(NULL, ",", &save)) {
        char *actual_copy = strdup(actual), *actual_save = NULL, *actual_option;
        int found = 0;

        if (!actual_copy)
            return 0;
        for (actual_option = strtok_r(actual_copy, ",", &actual_save); actual_option;
             actual_option = strtok_r(NULL, ",", &actual_save))
            if (!strcmp(actual_option, option)) {
                found = 1;
                break;
            }
        free(actual_copy);
        if (!found)
            return 0;
    }
    return 1;
}

static int fs_export_output_scan(const char *output, const char *path,
                                 const char *client, const char *options,
                                 int *entry_count)
{
    char *copy, *save = NULL, *line;
    char current_path[FS_MAX_PATH + 1] = {0};
    int found = 0;

    if (entry_count)
        *entry_count = 0;
    if (!output || !(copy = strdup(output)))
        return 0;
    for (line = strtok_r(copy, "\n", &save); line;
         line = strtok_r(NULL, "\n", &save)) {
        int continuation = isspace((unsigned char)line[0]);
        char *p = fs_trim(line), *end, *peer = NULL, *actual_options = NULL;

        if (*p == '/') {
            end = p;
            while (*end && !isspace((unsigned char)*end))
                end++;
            if (*end)
                *end++ = '\0';
            if (strlen(p) > FS_MAX_PATH) {
                current_path[0] = '\0';
                continue;
            }
            snprintf(current_path, sizeof(current_path), "%s", p);
            p = fs_trim(end);
            if (*p)
                peer = p;
        } else if (continuation && current_path[0] && *p) {
            peer = p;
        } else {
            current_path[0] = '\0';
        }
        if (!peer)
            continue;
        end = peer;
        while (*end && !isspace((unsigned char)*end) && *end != '(')
            end++;
        if (*end == '(') {
            *end++ = '\0';
            actual_options = end;
            end = strrchr(actual_options, ')');
            if (end)
                *end = '\0';
        } else {
            *end = '\0';
        }
        if (!peer[0])
            continue;
        if (entry_count)
            (*entry_count)++;
        if (path && client && !strcmp(current_path, path) &&
            (!strcmp(peer, client) ||
             (!strcmp(client, "*") && !strcmp(peer, "<world>"))) &&
            (!options || fs_export_options_include(actual_options, options)))
            found = 1;
    }
    free(copy);
    return found;
}

static int fs_nfs_runtime_probe(sqlite3 *db, struct fs_exec_result *result)
{
    sqlite3_stmt *st = NULL;
    char output[FS_SERVICE_OUTPUT_MAX];
    char *argv[] = { (char *)JMX_NFS_EXPORTFS_PATH, (char *)"-v", NULL };
    int enabled_count = 0, expected_entries = 0, actual_entries = 0, rc = -1;

    if (access(JMX_NFS_EXPORTFS_PATH, X_OK) != 0) {
        fs_probe_error(result, 127);
        return -1;
    }
    if (fs_exec_argv(argv, FS_SERVICE_TIMEOUT_MS, output, sizeof(output), result) != 0 ||
        result->output_truncated)
        return -1;
    (void)fs_export_output_scan(output, NULL, NULL, NULL, &actual_entries);
    if (fs_prepare(db, &st,
            "SELECT path,clients,options,id FROM nfs_export WHERE enabled=1 "
            "ORDER BY path,clients,id") != 0) {
        fs_probe_error(result, 65);
        return -1;
    }
    while (sqlite3_step(st) == SQLITE_ROW) {
        const char *path = fs_sql_text(st, 0, "");
        const char *clients = fs_sql_text(st, 1, "");
        const char *options = fs_sql_text(st, 2, "");
        char copy[513], *save = NULL, *client;

        char published[FS_MAX_PATH+1];
        if(!fs_binding_available(db,"nfs",fs_sql_text(st,3,""),path))continue;
        if(fs_binding_prepare(db,"nfs",fs_sql_text(st,3,""),path,published,sizeof published)!=1)goto out;
        path=published;
        enabled_count++;
        snprintf(copy, sizeof(copy), "%s", clients);
        for (client = strtok_r(copy, " ,\t", &save); client;
             client = strtok_r(NULL, " ,\t", &save)) {
            expected_entries++;
            if (!fs_export_output_scan(output, path, client, options, NULL)) {
                result->exit_code = 65;
                goto out;
            }
        }
    }
    if (actual_entries != expected_entries) {
        result->exit_code = 65;
        goto out;
    }
    if (enabled_count && !fs_nfsd_threads_positive(result))
        goto out;
    rc = 0;
out:
    sqlite3_finalize(st);
    return rc;
}

static int fs_runtime_probe(sqlite3 *db, const char *service,
                            struct fs_exec_result *result)
{
    return !strcmp(service, "samba") ?
        fs_samba_runtime_probe(db, result) : fs_nfs_runtime_probe(db, result);
}

static int fs_service_reload_or_restart(const char *script,
                                        struct fs_exec_result *result,
                                        const char **action)
{
    /* Revoke existing protocol sessions too: a reload may retain a directory
     * FD after its publication is removed or rebound. */
    *action = "restart";
    return fs_service_action(script,"restart",result);
}

static int fs_apply_new_config(sqlite3 *db, const char *service,
                               struct fs_snapshot *old_config,
                               struct fs_exec_result *result,
                               const char **action, const char **reason,
                               int *config_replaced)
{
    struct fs_buffer rendered = {0};
    const char *path, *script;
    int rc;

    *config_replaced = 0;
    fs_binding_sweep(db,service);
    if (!strcmp(service, "samba")) {
        path = JMX_SAMBA_CONFIG_PATH;
        script = JMX_SAMBA_INIT_PATH;
        rc = fs_render_samba(db, &rendered);
    } else {
        path = JMX_NFS_CONFIG_PATH;
        script = JMX_NFS_INIT_PATH;
        rc = fs_render_nfs(db, &rendered);
    }
    if (rc != 0) {
        *reason = "config_render_failed";
        fs_buffer_free(&rendered);
        return -1;
    }
    if (fs_config_preflight(!strcmp(service, "samba") ? "samba4" : "nfs",
                            rendered.data ? rendered.data : "", rendered.len) != 0) {
        *reason = "config_preflight_failed";
        fs_buffer_free(&rendered);
        return -1;
    }
    if (access(script, X_OK) != 0) {
        *reason = "service_runtime_unavailable";
        fs_buffer_free(&rendered);
        return -1;
    }
    if (fs_snapshot_read(path, old_config) != 0) {
        *reason = "existing_config_snapshot_failed";
        fs_buffer_free(&rendered);
        return -1;
    }
    if (fs_atomic_replace(path, rendered.data ? rendered.data : "", rendered.len,
                          old_config->existed && old_config->mode ? old_config->mode : 0600) != 0) {
        *reason = "config_atomic_replace_failed";
        fs_buffer_free(&rendered);
        return -1;
    }
    *config_replaced = 1;
    fs_buffer_free(&rendered);
    if (fs_service_reload_or_restart(script, result, action) != 0) {
        *reason = result->timed_out ? "service_apply_timeout" : "service_apply_failed";
        return -1;
    }
    if (!strcmp(service, "nfs")) {
        if (fs_nfs_exports_apply(db, result) != 0) {
            *reason = result->timed_out ? "runtime_config_apply_timeout" :
                      "runtime_config_apply_failed";
            return -1;
        }
        *action = "restart+exportfs";
    }
    if (fs_runtime_probe(db, service, result) != 0) {
        *reason = result->timed_out ? "runtime_probe_timeout" : "runtime_probe_failed";
        return -1;
    }
    *reason = "";
    return 0;
}

static int fs_restore_old_file(const char *service,
                               const struct fs_snapshot *old_config)
{
    const char *path = !strcmp(service, "samba") ?
        JMX_SAMBA_CONFIG_PATH : JMX_NFS_CONFIG_PATH;

    return fs_snapshot_restore(path, old_config);
}

static int fs_reload_old_service(sqlite3 *db, const char *service,
                                 struct fs_exec_result *result,
                                 const char **restore_action)
{
    const char *script = !strcmp(service, "samba") ?
        JMX_SAMBA_INIT_PATH : JMX_NFS_INIT_PATH;
    struct fs_buffer rendered={0};
    fs_binding_sweep(db,service);
    int rc=!strcmp(service,"samba")?fs_render_samba(db,&rendered):fs_render_nfs(db,&rendered);
    const char *config=!strcmp(service,"samba")?JMX_SAMBA_CONFIG_PATH:JMX_NFS_CONFIG_PATH;
    if(rc==0)rc=fs_atomic_replace(config,rendered.data,rendered.len,0600);
    fs_buffer_free(&rendered);
    if(rc==0)rc=fs_service_reload_or_restart(script,result,restore_action);

    if (rc == 0 && !strcmp(service, "nfs")) {
        rc = fs_nfs_exports_apply(db, result);
        *restore_action = "restart+exportfs";
    }
    return rc;
}

static int fs_meta_bump(sqlite3 *db)
{
    sqlite3_stmt *st = NULL;
    int rc = -1;

    if (fs_prepare(db, &st,
            "UPDATE file_service_meta SET revision=revision+1,last_error='',updated_at=?1 "
            "WHERE id=1") == 0) {
        sqlite3_bind_int64(st, 1, fs_now_s());
        rc = fs_step_done(st);
    }
    if (st)
        sqlite3_finalize(st);
    return rc;
}

static struct json_object *fs_write_failure(sqlite3 *db, const char *error,
                                             const char *reason,
                                             int rollback_failed,
                                             const struct fs_exec_result *result)
{
    struct json_object *data;

    if (db)
        (void)fs_sql_exec(db, "ROLLBACK");
    data = fs_error_detail(error, reason);
    json_object_object_add(data, "rolled_back", json_object_new_boolean(!rollback_failed));
    json_object_object_add(data, "rollback_failed", json_object_new_boolean(rollback_failed));
    if (result) {
        json_object_object_add(data, "service_exit_code",
                               json_object_new_int(result->exit_code));
        json_object_object_add(data, "service_timed_out",
                               json_object_new_boolean(result->timed_out));
        json_object_object_add(data, "service_output_truncated",
                               json_object_new_boolean(result->output_truncated));
    }
    return fs_envelope(FS_API_ERROR, data);
}

static struct json_object *fs_revision_conflict(const char *reason,
                                                int64_t expected_revision,
                                                int64_t current_revision)
{
    struct json_object *data = fs_error_detail("revision_conflict", reason);

    json_object_object_add(data, "expected_revision",
                           json_object_new_int64(expected_revision));
    json_object_object_add(data, "revision",
                           json_object_new_int64(current_revision));
    json_object_object_add(data, "changed", json_object_new_boolean(0));
    json_object_object_add(data, "persisted", json_object_new_boolean(0));
    json_object_object_add(data, "applied", json_object_new_boolean(0));
    return fs_envelope(FS_API_ERROR, data);
}

static int fs_revision_lookup(sqlite3 *db, const char *sql, const char *id,
                              int64_t *revision)
{
    sqlite3_stmt *st = NULL;
    int found = 0;

    if (fs_prepare(db, &st, sql) != 0)
        return -1;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW) {
        *revision = sqlite3_column_int64(st, 0);
        found = 1;
    }
    sqlite3_finalize(st);
    return found;
}

static int fs_meta_revision_lookup(sqlite3 *db, int64_t *revision)
{
    sqlite3_stmt *st = NULL;
    int found = 0;

    if (!revision || fs_prepare(db, &st,
            "SELECT revision FROM file_service_meta WHERE id=1") != 0)
        return -1;
    if (sqlite3_step(st) == SQLITE_ROW) {
        *revision = sqlite3_column_int64(st, 0);
        found = 1;
    }
    sqlite3_finalize(st);
    return found;
}

static struct json_object *fs_apply_failure_rollback(
    sqlite3 *db, const char *service, const struct fs_snapshot *old_config,
    int config_replaced, const char *error, const char *reason,
    const struct fs_exec_result *apply_result)
{
    struct fs_exec_result restore_result = {0};
    const char *restore_action = "";
    struct json_object *data;
    int file_restore_failed = 0, db_rollback_failed = 0, reload_failed = 0;

    /* Rollback order is intentional: file, DB transaction, then old service. */
    if (config_replaced)
        file_restore_failed = fs_restore_old_file(service, old_config) != 0;
    db_rollback_failed = fs_sql_exec(db, "ROLLBACK") != 0;
    if (config_replaced && !file_restore_failed && !db_rollback_failed)
        reload_failed = fs_reload_old_service(db, service, &restore_result,
                                               &restore_action) != 0;
    if (config_replaced && !file_restore_failed && !db_rollback_failed &&
        !reload_failed)
        reload_failed = fs_runtime_probe(db, service, &restore_result) != 0;
    data = fs_error_detail(error, reason);
    json_object_object_add(data, "rolled_back",
        json_object_new_boolean(!file_restore_failed && !db_rollback_failed && !reload_failed));
    json_object_object_add(data, "rollback_failed",
        json_object_new_boolean(file_restore_failed || db_rollback_failed || reload_failed));
    json_object_object_add(data, "config_restored",
                           json_object_new_boolean(!config_replaced || !file_restore_failed));
    json_object_object_add(data, "db_rolled_back",
                           json_object_new_boolean(!db_rollback_failed));
    json_object_object_add(data, "old_service_reloaded",
        json_object_new_boolean(!config_replaced || (!file_restore_failed && !reload_failed)));
    if (restore_action[0])
        json_object_object_add(data, "rollback_service_action",
                               json_object_new_string(restore_action));
    if (apply_result) {
        json_object_object_add(data, "service_exit_code",
                               json_object_new_int(apply_result->exit_code));
        json_object_object_add(data, "service_timed_out",
                               json_object_new_boolean(apply_result->timed_out));
        json_object_object_add(data, "service_output_truncated",
                               json_object_new_boolean(apply_result->output_truncated));
    }
    if (config_replaced && !file_restore_failed && reload_failed) {
        json_object_object_add(data, "rollback_service_exit_code",
                               json_object_new_int(restore_result.exit_code));
        json_object_object_add(data, "rollback_service_timed_out",
                               json_object_new_boolean(restore_result.timed_out));
    }
    return fs_envelope(FS_API_ERROR, data);
}

static int fs_samba_load(sqlite3 *db, const char *id,
                          struct fs_samba_share *share)
{
    sqlite3_stmt *st = NULL;
    int found = 0;

    memset(share, 0, sizeof(*share));
    if (fs_prepare(db, &st,
            "SELECT id,name,path,enabled,read_only,browseable,network_discovery,guest_access,"
            "allowed_users_json,note,revision,created_at,updated_at FROM samba_share WHERE id=?1") != 0)
        return -1;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW) {
        snprintf(share->id, sizeof(share->id), "%s", fs_sql_text(st, 0, ""));
        snprintf(share->name, sizeof(share->name), "%s", fs_sql_text(st, 1, ""));
        snprintf(share->path, sizeof(share->path), "%s", fs_sql_text(st, 2, ""));
        share->enabled = sqlite3_column_int(st, 3);
        share->read_only = sqlite3_column_int(st, 4);
        share->browseable = sqlite3_column_int(st, 5);
        share->network_discovery = sqlite3_column_int(st, 6);
        share->guest_access = sqlite3_column_int(st, 7);
        share->allowed_users_json = strdup(fs_sql_text(st, 8, "[]"));
        snprintf(share->note, sizeof(share->note), "%s", fs_sql_text(st, 9, ""));
        share->revision = sqlite3_column_int64(st, 10);
        share->created_at = sqlite3_column_int64(st, 11);
        share->updated_at = sqlite3_column_int64(st, 12);
        found = share->allowed_users_json ? 1 : -1;
    }
    sqlite3_finalize(st);
    return found;
}

static void fs_samba_free(struct fs_samba_share *share)
{
    free(share->allowed_users_json);
    share->allowed_users_json = NULL;
}

static int fs_nfs_load(sqlite3 *db, const char *id, struct fs_nfs_export *item)
{
    sqlite3_stmt *st = NULL;
    int found = 0;

    memset(item, 0, sizeof(*item));
    if (fs_prepare(db, &st,
            "SELECT id,enabled,path,clients,options,note,revision,created_at,updated_at "
            "FROM nfs_export WHERE id=?1") != 0)
        return -1;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW) {
        snprintf(item->id, sizeof(item->id), "%s", fs_sql_text(st, 0, ""));
        item->enabled = sqlite3_column_int(st, 1);
        snprintf(item->path, sizeof(item->path), "%s", fs_sql_text(st, 2, ""));
        snprintf(item->clients, sizeof(item->clients), "%s", fs_sql_text(st, 3, ""));
        snprintf(item->options, sizeof(item->options), "%s", fs_sql_text(st, 4, ""));
        snprintf(item->note, sizeof(item->note), "%s", fs_sql_text(st, 5, ""));
        item->revision = sqlite3_column_int64(st, 6);
        item->created_at = sqlite3_column_int64(st, 7);
        item->updated_at = sqlite3_column_int64(st, 8);
        found = 1;
    }
    sqlite3_finalize(st);
    return found;
}

/* Store per-user restrictions in the same transaction as the canonical share. */
static int fs_samba_acl_update(sqlite3 *db, const char *id,
                                struct json_object *payload, const char *allowed_json)
{
    struct json_object *value = NULL, *readers = NULL, *allowed = fs_json_array_text(allowed_json);
    sqlite3_stmt *st = NULL;
    int rc = -1;
    if (json_object_object_get_ex(payload, "read_only_users", &value)) {
        struct json_object *wrapped = json_object_new_object();
        char *encoded = NULL; int present = 0;
        json_object_object_add(wrapped, "allowed_users", json_object_get(value));
        int valid = fs_allowed_users_json(wrapped, &encoded, &present) == 0 && present;
        json_object_put(wrapped);
        if (!valid) { free(encoded); goto out; }
        readers = fs_json_array_text(encoded); free(encoded);
    } else {
        if (fs_prepare(db, &st, "SELECT read_only_users_json FROM samba_share_acl WHERE share_id=?1") != 0) goto out;
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        int step = sqlite3_step(st);
        if (step != SQLITE_ROW && step != SQLITE_DONE) goto out;
        readers = fs_json_array_text(step == SQLITE_ROW ? fs_sql_text(st, 0, "[]") : "[]");
        sqlite3_finalize(st); st = NULL;
    }
    for (size_t i = 0; i < json_object_array_length(readers); i++) {
        const char *name = json_object_get_string(json_object_array_get_idx(readers, i));
        int found = 0;
        for (size_t j = 0; j < json_object_array_length(allowed); j++)
            if (!strcmp(name, json_object_get_string(json_object_array_get_idx(allowed, j)))) found = 1;
        if (!found) goto out;
    }
    if (fs_prepare(db, &st, "INSERT INTO samba_share_acl(share_id,read_only_users_json) VALUES(?1,?2) "
        "ON CONFLICT(share_id) DO UPDATE SET read_only_users_json=excluded.read_only_users_json") != 0) goto out;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, json_object_to_json_string_ext(readers, JSON_C_TO_STRING_PLAIN), -1, SQLITE_TRANSIENT);
    rc = fs_step_done(st);
out:
    if (st) sqlite3_finalize(st);
    if (readers) json_object_put(readers);
    json_object_put(allowed);
    return rc;
}

struct json_object *jmx_samba_share_upsert(const char *id,
                                            struct json_object *req)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *st = NULL;
    struct fs_samba_share share;
    struct fs_snapshot old_config = {0};
    struct fs_exec_result apply_result = {0};
    struct json_object *payload = fs_payload(req), *response = NULL, *result_data;
    const char *name = NULL, *path = NULL, *note = NULL;
    const char *apply_action = "", *reason = "";
    char generated_id[FS_MAX_ID + 1], canonical[FS_MAX_PATH + 1];
    char *users_json = NULL;
    int create = !id || !id[0], found = 0, present, bool_value;
    int users_present = 0, config_replaced = 0;
    int64_t expected_revision = 0, current_revision = 0, new_revision, meta_revision = 0;
    int64_t now = fs_now_s();

    memset(&share, 0, sizeof(share));
    if (!fs_confirmed(payload))
        return fs_error("confirmation_required", "confirm_true_required");
    if (!payload || !json_object_is_type(payload, json_type_object))
        return fs_error("invalid_request", "request_object_required");
    if (!create && !fs_id_ok(id))
        return fs_error("invalid_id", "samba_share_id_invalid");
    if (!create) {
        if (fs_json_positive_int64(payload, "expected_revision",
                                   &expected_revision, &present) != 0)
            return fs_error("invalid_expected_revision",
                            "expected_revision_must_be_positive_integer");
        if (!present)
            return fs_error("missing_expected_revision",
                            "expected_revision_is_required_for_update");
    }
    if (fs_db_open(&db) != 0)
        return fs_error("storage_unavailable", "config_db_open_or_schema_failed");
    if (create) {
        if (fs_random_id(db, "samba", "samba_share", generated_id,
                         sizeof(generated_id)) != 0) {
            response = fs_error("id_generation_failed", "secure_random_id_unavailable");
            goto out;
        }
        id = generated_id;
        share.enabled = 1;
        share.browseable = 1;
        share.network_discovery = 1;
        share.allowed_users_json = strdup("[]");
        share.created_at = now;
    } else {
        found = fs_samba_load(db, id, &share);
        if (found <= 0) {
            response = fs_error(found < 0 ? "storage_error" : "not_found",
                                found < 0 ? "samba_share_read_failed" : "samba_share_not_found");
            goto out;
        }
    }
    snprintf(share.id, sizeof(share.id), "%s", id);
    if (fs_json_string(payload, "name", &name, &present) != 0 ||
        (create && !present) || (present && !fs_samba_name_ok(name))) {
        response = fs_error("invalid_name", "samba_share_name_invalid");
        goto out;
    }
    if (present)
        snprintf(share.name, sizeof(share.name), "%s", name);
    if (fs_json_string(payload, "path", &path, &present) != 0 ||
        (create && !present) ||
        (present && !fs_share_path_update_ok(path, share.path, payload, canonical, sizeof(canonical)))) {
        response = fs_error("invalid_path", "share_path_must_be_safe_absolute_directory");
        goto out;
    }
    if (present)
        snprintf(share.path, sizeof(share.path), "%s", canonical);
    if (fs_json_string(payload, "note", &note, &present) != 0 ||
        (present && !fs_text_ok(note, 256, 0))) {
        response = fs_error("invalid_note", "samba_share_note_invalid");
        goto out;
    }
    if (present)
        snprintf(share.note, sizeof(share.note), "%s", note);
#define FS_READ_SHARE_BOOL(key, field) \
    do { \
        if (fs_json_bool(payload, key, &bool_value, &present) != 0) { \
            response = fs_error("invalid_boolean", key "_must_be_boolean"); \
            goto out; \
        } \
        if (present) share.field = bool_value; \
    } while (0)
    FS_READ_SHARE_BOOL("enabled", enabled);
    FS_READ_SHARE_BOOL("read_only", read_only);
    FS_READ_SHARE_BOOL("browseable", browseable);
    FS_READ_SHARE_BOOL("network_discovery", network_discovery);
    FS_READ_SHARE_BOOL("guest_access", guest_access);
#undef FS_READ_SHARE_BOOL
    if (fs_allowed_users_json(payload, &users_json, &users_present) != 0) {
        response = fs_error("invalid_allowed_users",
                            "allowed_users_must_be_unique_existing_local_users");
        goto out;
    }
    if (users_present) {
        free(share.allowed_users_json);
        share.allowed_users_json = users_json;
        users_json = NULL;
    }
    if (!share.allowed_users_json)
        share.allowed_users_json = strdup("[]");
    if (!share.name[0] || !share.path[0] || !share.allowed_users_json) {
        response = fs_error("invalid_request", "required_samba_share_fields_missing");
        goto out;
    }
    if (fs_sql_exec(db, "BEGIN IMMEDIATE") != 0) {
        response = fs_error("storage_busy", "file_service_transaction_could_not_start");
        goto out;
    }
    /* Serialize ACL validation with dedicated-account creation/deletion. */
    if (users_present) {
        char *checked = NULL; int has_users = 0;
        if (fs_allowed_users_json(payload, &checked, &has_users) != 0) {
            response = fs_error("invalid_allowed_users", "allowed_users_changed_during_write");
            (void)fs_sql_exec(db, "ROLLBACK");
            goto out;
        }
        free(checked);
    }
    /* Disabled legacy shares must still be revocable when their disk is lost. */
    if (share.enabled && !share.guest_access) {
        struct json_object *acl = fs_json_array_text(share.allowed_users_json);
        int count = 0;
        int broad = json_object_array_length(acl) == 0;
        json_object_put(acl);
        if (broad && (create || fs_table_count(db, "file_share_account", &count) != 0 || count > 0)) {
            response = fs_error("explicit_acl_required", "private_share_requires_explicit_users");
            (void)fs_sql_exec(db, "ROLLBACK");
            goto out;
        }
    }
    if (fs_prepare(db, &st, create ?
            "INSERT INTO samba_share"
            "(id,name,path,enabled,read_only,browseable,network_discovery,guest_access,"
            "allowed_users_json,note,revision,created_at,updated_at)"
            " VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,1,?11,?11)" :
            "UPDATE samba_share SET name=?2,path=?3,enabled=?4,read_only=?5,"
            "browseable=?6,network_discovery=?7,guest_access=?8,allowed_users_json=?9,"
            "note=?10,revision=revision+1,updated_at=?11 WHERE id=?1 AND revision=?12") != 0) {
        response = fs_write_failure(db, "storage_error", "samba_share_prepare_failed",
                                    0, NULL);
        goto out;
    }
    sqlite3_bind_text(st, 1, share.id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, share.name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, share.path, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 4, share.enabled);
    sqlite3_bind_int(st, 5, share.read_only);
    sqlite3_bind_int(st, 6, share.browseable);
    sqlite3_bind_int(st, 7, share.network_discovery);
    sqlite3_bind_int(st, 8, share.guest_access);
    sqlite3_bind_text(st, 9, share.allowed_users_json, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 10, share.note, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 11, now);
    if (!create)
        sqlite3_bind_int64(st, 12, expected_revision);
    if (fs_step_done(st) != 0) {
        const char *constraint = sqlite3_extended_errcode(db) == SQLITE_CONSTRAINT_UNIQUE ?
            "samba_share_name_must_be_unique" : "samba_share_write_failed";
        sqlite3_finalize(st); st = NULL;
        response = fs_write_failure(db, "storage_error", constraint, 0, NULL);
        goto out;
    }
    found = sqlite3_changes(db);
    sqlite3_finalize(st); st = NULL;
    if (!create && found != 1) {
        found = fs_revision_lookup(db,
            "SELECT revision FROM samba_share WHERE id=?1", id, &current_revision);
        (void)fs_sql_exec(db, "ROLLBACK");
        response = found < 0 ?
            fs_error("storage_error", "samba_share_revision_read_failed") :
            found == 0 ? fs_error("not_found", "samba_share_not_found") :
            fs_revision_conflict("samba_share_revision_mismatch",
                                 expected_revision, current_revision);
        goto out;
    }
    if (fs_samba_acl_update(db, share.id, payload, share.allowed_users_json) != 0) {
        response = fs_write_failure(db, "invalid_read_only_users",
                                   "read_only_users_must_be_unique_members_of_allowed_users", 0, NULL);
        goto out;
    }
    if(fs_binding_update(db,"samba",share.id,share.path,share.enabled,payload)!=0){
        response=fs_write_failure(db,"directory_binding_changed","reselect_directory_or_disable_share",0,NULL);goto out;
    }
    new_revision = create ? 1 : expected_revision + 1;
    fs_meta_bump(db);
    if (fs_meta_revision_lookup(db, &meta_revision) != 1) {
        response = fs_write_failure(db, "storage_error",
                                    "file_service_meta_revision_read_failed", 0, NULL);
        goto out;
    }
    if (fs_apply_new_config(db, "samba", &old_config, &apply_result,
                            &apply_action, &reason, &config_replaced) != 0) {
        response = fs_apply_failure_rollback(db, "samba", &old_config,
            config_replaced, "service_apply_failed", reason, &apply_result);
        goto out;
    }
    if (fs_operation_receipt(db, share.id, new_revision, 0) != 0 ||
        fs_sql_exec(db, "COMMIT") != 0) {
        response = fs_apply_failure_rollback(db, "samba", &old_config,
            config_replaced, "storage_error", "commit_failed_after_apply", &apply_result);
        goto out;
    }
    result_data = json_object_new_object();
    fs_add_contract(result_data);
    json_object_object_add(result_data, "id", json_object_new_string(share.id));
    json_object_object_add(result_data, "created", json_object_new_boolean(create));
    json_object_object_add(result_data, "changed", json_object_new_boolean(1));
    json_object_object_add(result_data, "revision", json_object_new_int64(new_revision));
    json_object_object_add(result_data, "meta_revision", json_object_new_int64(meta_revision));
    json_object_object_add(result_data, "applied", json_object_new_boolean(1));
    json_object_object_add(result_data, "service_action",
                           json_object_new_string(apply_action));
    response = fs_success(result_data);
out:
    if (st)
        sqlite3_finalize(st);
    free(users_json);
    fs_samba_free(&share);
    fs_snapshot_free(&old_config);
    if (db)
        sqlite3_close(db);
    return response ? response : fs_error("internal_error", "samba_share_upsert_failed");
}

struct json_object *jmx_samba_share_delete(const char *id,
                                            struct json_object *req)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *st = NULL;
    struct fs_snapshot old_config = {0};
    struct fs_exec_result apply_result = {0};
    struct json_object *payload = fs_payload(req), *response = NULL, *data;
    const char *action = "", *reason = "";
    int found, present, config_replaced = 0;
    int64_t expected_revision = 0, current_revision = 0, meta_revision = 0;

    if (!fs_confirmed(req))
        return fs_error("confirmation_required", "confirm_true_required");
    if (!fs_id_ok(id))
        return fs_error("invalid_id", "samba_share_id_invalid");
    if (fs_json_positive_int64(payload, "expected_revision",
                               &expected_revision, &present) != 0)
        return fs_error("invalid_expected_revision",
                        "expected_revision_must_be_positive_integer");
    if (!present)
        return fs_error("missing_expected_revision",
                        "expected_revision_is_required_for_delete");
    if (fs_db_open(&db) != 0)
        return fs_error("storage_unavailable", "config_db_open_or_schema_failed");
    if (fs_sql_exec(db, "BEGIN IMMEDIATE") != 0) {
        response = fs_error("storage_busy", "file_service_transaction_could_not_start");
        goto out;
    }
    if (fs_prepare(db, &st,
                   "DELETE FROM samba_share WHERE id=?1 AND revision=?2") != 0) {
        response = fs_write_failure(db, "storage_error", "samba_share_delete_prepare_failed", 0, NULL);
        goto out;
    }
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, expected_revision);
    if (fs_step_done(st) != 0) {
        sqlite3_finalize(st); st = NULL;
        response = fs_write_failure(db, "storage_error", "samba_share_delete_failed", 0, NULL);
        goto out;
    }
    found = sqlite3_changes(db);
    sqlite3_finalize(st); st = NULL;
    if (!found) {
        found = fs_revision_lookup(db,
            "SELECT revision FROM samba_share WHERE id=?1", id, &current_revision);
        (void)fs_sql_exec(db, "ROLLBACK");
        response = found < 0 ?
            fs_error("storage_error", "samba_share_revision_read_failed") :
            found == 0 ? fs_error("not_found", "samba_share_not_found") :
            fs_revision_conflict("samba_share_revision_mismatch",
                                 expected_revision, current_revision);
        goto out;
    }
    fs_meta_bump(db);
    if (fs_meta_revision_lookup(db, &meta_revision) != 1) {
        response = fs_write_failure(db, "storage_error",
                                    "file_service_meta_revision_read_failed", 0, NULL);
        goto out;
    }
    if (fs_apply_new_config(db, "samba", &old_config, &apply_result,
                            &action, &reason, &config_replaced) != 0) {
        response = fs_apply_failure_rollback(db, "samba", &old_config,
            config_replaced, "service_apply_failed", reason, &apply_result);
        goto out;
    }
    if (fs_operation_receipt(db, id, expected_revision, 1) != 0 ||
        fs_sql_exec(db, "COMMIT") != 0) {
        response = fs_apply_failure_rollback(db, "samba", &old_config,
            config_replaced, "storage_error", "commit_failed_after_apply", &apply_result);
        goto out;
    }
    data = json_object_new_object(); fs_add_contract(data);
    json_object_object_add(data, "id", json_object_new_string(id));
    json_object_object_add(data, "deleted", json_object_new_boolean(1));
    json_object_object_add(data, "deleted_revision",
                           json_object_new_int64(expected_revision));
    json_object_object_add(data, "meta_revision", json_object_new_int64(meta_revision));
    json_object_object_add(data, "applied", json_object_new_boolean(1));
    json_object_object_add(data, "service_action", json_object_new_string(action));
    response = fs_success(data);
out:
    if (st) sqlite3_finalize(st);
    fs_snapshot_free(&old_config);
    if (db) sqlite3_close(db);
    return response ? response : fs_error("internal_error", "samba_share_delete_failed");
}

struct json_object *jmx_nfs_export_upsert(const char *id,
                                          struct json_object *req)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *st = NULL;
    struct fs_nfs_export item;
    struct fs_snapshot old_config = {0};
    struct fs_exec_result apply_result = {0};
    struct json_object *payload = fs_payload(req), *response = NULL, *data;
    const char *path = NULL, *clients = NULL, *options = NULL, *note = NULL;
    const char *action = "", *reason = "";
    char generated_id[FS_MAX_ID + 1], canonical[FS_MAX_PATH + 1];
    int create = !id || !id[0], present, value, found, config_replaced = 0;
    int64_t expected_revision = 0, current_revision = 0, new_revision, meta_revision = 0;
    int64_t now = fs_now_s();

    memset(&item, 0, sizeof(item));
    if (!fs_confirmed(payload))
        return fs_error("confirmation_required", "confirm_true_required");
    if (!payload || !json_object_is_type(payload, json_type_object))
        return fs_error("invalid_request", "request_object_required");
    if (!create && !fs_id_ok(id))
        return fs_error("invalid_id", "nfs_export_id_invalid");
    if (!create) {
        if (fs_json_positive_int64(payload, "expected_revision",
                                   &expected_revision, &present) != 0)
            return fs_error("invalid_expected_revision",
                            "expected_revision_must_be_positive_integer");
        if (!present)
            return fs_error("missing_expected_revision",
                            "expected_revision_is_required_for_update");
    }
    if (fs_db_open(&db) != 0)
        return fs_error("storage_unavailable", "config_db_open_or_schema_failed");
    if (create) {
        if (fs_random_id(db, "nfs", "nfs_export", generated_id, sizeof(generated_id)) != 0) {
            response = fs_error("id_generation_failed", "secure_random_id_unavailable");
            goto out;
        }
        id = generated_id;
        item.enabled = 1;
        item.created_at = now;
    } else {
        found = fs_nfs_load(db, id, &item);
        if (found <= 0) {
            response = fs_error(found < 0 ? "storage_error" : "not_found",
                                found < 0 ? "nfs_export_read_failed" : "nfs_export_not_found");
            goto out;
        }
    }
    snprintf(item.id, sizeof(item.id), "%s", id);
    if (fs_json_string(payload, "path", &path, &present) != 0 ||
        (create && !present) ||
        (present && !fs_share_path_update_ok(path, item.path, payload, canonical, sizeof(canonical)))) {
        response = fs_error("invalid_path", "export_path_must_be_safe_absolute_directory");
        goto out;
    }
    if (present) snprintf(item.path, sizeof(item.path), "%s", canonical);
    if (fs_json_string(payload, "clients", &clients, &present) != 0 ||
        (create && !present) || (present && !fs_nfs_clients_ok(clients))) {
        response = fs_error("invalid_clients", "nfs_clients_invalid");
        goto out;
    }
    if (present) snprintf(item.clients, sizeof(item.clients), "%s", clients);
    if (fs_json_string(payload, "options", &options, &present) != 0 ||
        (create && !present) || (present && !fs_nfs_options_ok(options))) {
        response = fs_error("invalid_options", "nfs_options_not_in_allowlist");
        goto out;
    }
    if (present) snprintf(item.options, sizeof(item.options), "%s", options);
    if (fs_json_string(payload, "note", &note, &present) != 0 ||
        (present && !fs_text_ok(note, 256, 0))) {
        response = fs_error("invalid_note", "nfs_export_note_invalid");
        goto out;
    }
    if (present) snprintf(item.note, sizeof(item.note), "%s", note);
    if (fs_json_bool(payload, "enabled", &value, &present) != 0) {
        response = fs_error("invalid_boolean", "enabled_must_be_boolean");
        goto out;
    }
    if (present) item.enabled = value;
    if (fs_sql_exec(db, "BEGIN IMMEDIATE") != 0) {
        response = fs_error("storage_busy", "file_service_transaction_could_not_start");
        goto out;
    }
    if (fs_prepare(db, &st, create ?
            "INSERT INTO nfs_export(id,enabled,path,clients,options,note,revision,created_at,updated_at)"
            " VALUES(?1,?2,?3,?4,?5,?6,1,?7,?7)" :
            "UPDATE nfs_export SET enabled=?2,path=?3,clients=?4,options=?5,note=?6,"
            "revision=revision+1,updated_at=?7 WHERE id=?1 AND revision=?8") != 0) {
        response = fs_write_failure(db, "storage_error", "nfs_export_prepare_failed", 0, NULL);
        goto out;
    }
    sqlite3_bind_text(st, 1, item.id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 2, item.enabled);
    sqlite3_bind_text(st, 3, item.path, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 4, item.clients, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 5, item.options, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 6, item.note, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 7, now);
    if (!create)
        sqlite3_bind_int64(st, 8, expected_revision);
    if (fs_step_done(st) != 0) {
        const char *constraint = sqlite3_extended_errcode(db) == SQLITE_CONSTRAINT_UNIQUE ?
            "nfs_export_path_clients_must_be_unique" : "nfs_export_write_failed";
        sqlite3_finalize(st); st = NULL;
        response = fs_write_failure(db, "storage_error", constraint, 0, NULL);
        goto out;
    }
    found = sqlite3_changes(db);
    sqlite3_finalize(st); st = NULL;
    if (!create && found != 1) {
        found = fs_revision_lookup(db,
            "SELECT revision FROM nfs_export WHERE id=?1", id, &current_revision);
        (void)fs_sql_exec(db, "ROLLBACK");
        response = found < 0 ?
            fs_error("storage_error", "nfs_export_revision_read_failed") :
            found == 0 ? fs_error("not_found", "nfs_export_not_found") :
            fs_revision_conflict("nfs_export_revision_mismatch",
                                 expected_revision, current_revision);
        goto out;
    }
    if(fs_binding_update(db,"nfs",item.id,item.path,item.enabled,payload)!=0){
        response=fs_write_failure(db,"directory_binding_changed","reselect_directory_or_disable_share",0,NULL);goto out;
    }
    new_revision = create ? 1 : expected_revision + 1;
    fs_meta_bump(db);
    if (fs_meta_revision_lookup(db, &meta_revision) != 1) {
        response = fs_write_failure(db, "storage_error",
                                    "file_service_meta_revision_read_failed", 0, NULL);
        goto out;
    }
    if (fs_apply_new_config(db, "nfs", &old_config, &apply_result,
                            &action, &reason, &config_replaced) != 0) {
        response = fs_apply_failure_rollback(db, "nfs", &old_config,
            config_replaced, "service_apply_failed", reason, &apply_result);
        goto out;
    }
    if (fs_operation_receipt(db, item.id, new_revision, 0) != 0 ||
        fs_sql_exec(db, "COMMIT") != 0) {
        response = fs_apply_failure_rollback(db, "nfs", &old_config,
            config_replaced, "storage_error", "commit_failed_after_apply", &apply_result);
        goto out;
    }
    data = json_object_new_object(); fs_add_contract(data);
    json_object_object_add(data, "id", json_object_new_string(item.id));
    json_object_object_add(data, "created", json_object_new_boolean(create));
    json_object_object_add(data, "changed", json_object_new_boolean(1));
    json_object_object_add(data, "revision", json_object_new_int64(new_revision));
    json_object_object_add(data, "meta_revision", json_object_new_int64(meta_revision));
    json_object_object_add(data, "applied", json_object_new_boolean(1));
    json_object_object_add(data, "service_action", json_object_new_string(action));
    response = fs_success(data);
out:
    if (st) sqlite3_finalize(st);
    fs_snapshot_free(&old_config);
    if (db) sqlite3_close(db);
    return response ? response : fs_error("internal_error", "nfs_export_upsert_failed");
}

struct json_object *jmx_nfs_export_delete(const char *id,
                                          struct json_object *req)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *st = NULL;
    struct fs_snapshot old_config = {0};
    struct fs_exec_result apply_result = {0};
    struct json_object *payload = fs_payload(req), *response = NULL, *data;
    const char *action = "", *reason = "";
    int found, present, config_replaced = 0;
    int64_t expected_revision = 0, current_revision = 0, meta_revision = 0;

    if (!fs_confirmed(req))
        return fs_error("confirmation_required", "confirm_true_required");
    if (!fs_id_ok(id))
        return fs_error("invalid_id", "nfs_export_id_invalid");
    if (fs_json_positive_int64(payload, "expected_revision",
                               &expected_revision, &present) != 0)
        return fs_error("invalid_expected_revision",
                        "expected_revision_must_be_positive_integer");
    if (!present)
        return fs_error("missing_expected_revision",
                        "expected_revision_is_required_for_delete");
    if (fs_db_open(&db) != 0)
        return fs_error("storage_unavailable", "config_db_open_or_schema_failed");
    if (fs_sql_exec(db, "BEGIN IMMEDIATE") != 0) {
        response = fs_error("storage_busy", "file_service_transaction_could_not_start");
        goto out;
    }
    if (fs_prepare(db, &st,
                   "DELETE FROM nfs_export WHERE id=?1 AND revision=?2") != 0) {
        response = fs_write_failure(db, "storage_error", "nfs_export_delete_prepare_failed", 0, NULL);
        goto out;
    }
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, expected_revision);
    if (fs_step_done(st) != 0) {
        sqlite3_finalize(st); st = NULL;
        response = fs_write_failure(db, "storage_error", "nfs_export_delete_failed", 0, NULL);
        goto out;
    }
    found = sqlite3_changes(db);
    sqlite3_finalize(st); st = NULL;
    if (!found) {
        found = fs_revision_lookup(db,
            "SELECT revision FROM nfs_export WHERE id=?1", id, &current_revision);
        (void)fs_sql_exec(db, "ROLLBACK");
        response = found < 0 ?
            fs_error("storage_error", "nfs_export_revision_read_failed") :
            found == 0 ? fs_error("not_found", "nfs_export_not_found") :
            fs_revision_conflict("nfs_export_revision_mismatch",
                                 expected_revision, current_revision);
        goto out;
    }
    fs_meta_bump(db);
    if (fs_meta_revision_lookup(db, &meta_revision) != 1) {
        response = fs_write_failure(db, "storage_error",
                                    "file_service_meta_revision_read_failed", 0, NULL);
        goto out;
    }
    if (fs_apply_new_config(db, "nfs", &old_config, &apply_result,
                            &action, &reason, &config_replaced) != 0) {
        response = fs_apply_failure_rollback(db, "nfs", &old_config,
            config_replaced, "service_apply_failed", reason, &apply_result);
        goto out;
    }
    if (fs_operation_receipt(db, id, expected_revision, 1) != 0 ||
        fs_sql_exec(db, "COMMIT") != 0) {
        response = fs_apply_failure_rollback(db, "nfs", &old_config,
            config_replaced, "storage_error", "commit_failed_after_apply", &apply_result);
        goto out;
    }
    data = json_object_new_object(); fs_add_contract(data);
    json_object_object_add(data, "id", json_object_new_string(id));
    json_object_object_add(data, "deleted", json_object_new_boolean(1));
    json_object_object_add(data, "deleted_revision",
                           json_object_new_int64(expected_revision));
    json_object_object_add(data, "meta_revision", json_object_new_int64(meta_revision));
    json_object_object_add(data, "applied", json_object_new_boolean(1));
    json_object_object_add(data, "service_action", json_object_new_string(action));
    response = fs_success(data);
out:
    if (st) sqlite3_finalize(st);
    fs_snapshot_free(&old_config);
    if (db) sqlite3_close(db);
    return response ? response : fs_error("internal_error", "nfs_export_delete_failed");
}

/* Explicit protocol commands. The database write lock also serializes share applies. */
struct json_object *jmx_file_service_action(const char *service, struct json_object *req)
{
    struct json_object *payload = fs_payload(req), *response = NULL, *data;
    struct fs_exec_result result = {0}, restore = {0};
    struct fs_buffer rendered = {0};
    struct fs_snapshot snapshot = {0};
    sqlite3 *db = NULL;
    const char *script, *action = NULL;
    int present = 0, in_tx = 0, before_running, before_enabled, rc = -1;
    int replaced = 0;
    const char *config_path = NULL;
    int64_t expected = 0, revision = 0;
    if(service && !strcmp(service,"webdav"))return fs_dav_action(req);
    if(service && !strcmp(service,"ftp"))return fs_ftp_action(req);
    if (!service || !(script = fs_control_script(service)))
        return fs_error("capability_disabled", "protocol_control_not_available");
    config_path = !strcmp(service, "samba") ? JMX_SAMBA_CONFIG_PATH : JMX_NFS_CONFIG_PATH;
    if (!fs_confirmed(req)) return fs_error("confirmation_required", "confirm_true_required");
    if (fs_json_string(payload, "action", &action, &present) != 0 || !present ||
        (strcmp(action, "start") && strcmp(action, "stop") && strcmp(action, "restart") && strcmp(action, "enable") && strcmp(action, "disable")))
        return fs_error("invalid_action", "start_stop_restart_enable_disable_only");
    if (fs_json_positive_int64(payload, "expected_revision", &expected, &present) != 0 || !present)
        return fs_error("missing_expected_revision", "control_revision_required");
    if (access(script, X_OK) != 0) return fs_error("runtime_not_installed", "protocol_init_missing");
    if (fs_db_open(&db) != 0) return fs_error("storage_unavailable", "config_db_open_failed");
    if (fs_sql_exec(db, "BEGIN IMMEDIATE") != 0) { response = fs_error("storage_busy", "protocol_operation_in_progress"); goto out; }
    in_tx = 1;
    if (fs_meta_revision_lookup(db, &revision) != 1) goto out;
    if (revision != expected) { response = fs_revision_conflict("file_service_changed", expected, revision); goto out; }
    before_running = fs_control_running(service);
    rc = fs_service_action(script, "enabled", &result);
    if (rc != 0 && result.exit_code != 1) { response = fs_error("runtime_probe_failed", "autostart_state_unknown"); goto out; }
    before_enabled = rc == 0;
    int autostart = !strcmp(action, "enable") || !strcmp(action, "disable");
    if (!autostart && strcmp(action, "stop")) {
        if ((!strcmp(service, "samba") ? fs_render_samba(db, &rendered) : fs_render_nfs(db, &rendered)) != 0 ||
            fs_config_preflight(!strcmp(service, "samba") ? "samba4" : "nfs", rendered.data, rendered.len) != 0) {
            response = fs_error("config_preflight_failed", "shared_directories_or_config_unavailable"); goto out;
        }
        if (!strcmp(service, "nfs") && !fs_service_running(JMX_RPC_BIND_INIT_PATH)) {
            response = fs_error("dependency_unavailable", "rpcbind_must_be_running"); goto out;
        }
        if (fs_snapshot_read(config_path, &snapshot) != 0 ||
            fs_atomic_replace(config_path, rendered.data, rendered.len,
                              snapshot.existed ? snapshot.mode : 0600) != 0) {
            response = fs_error("config_replace_failed", "protocol_projection_failed"); goto out;
        }
        replaced = 1;
    }
    rc = fs_service_action(script, action, &result);
    if (rc == 0 && !autostart && strcmp(action, "stop")) {
        if (!strcmp(service, "nfs")) rc = fs_nfs_exports_apply(db, &result);
        if (rc == 0) rc = fs_runtime_probe(db, service, &result);
    }
    if (rc == 0 && autostart) {
        int actual = fs_service_action(script, "enabled", &result);
        rc = ((actual == 0) == !strcmp(action, "enable") &&
              (actual == 0 || result.exit_code == 1)) ? 0 : -1;
    }
    if (rc == 0 && !strcmp(action, "stop") && fs_control_running(service)) rc = -1;
    if (rc == 0) {
        fs_meta_bump(db);
        if (fs_sql_exec(db, "COMMIT") == 0) {
            in_tx = 0;
            data = json_object_new_object();
            json_object_object_add(data, "service", json_object_new_string(service));
            json_object_object_add(data, "service_action", json_object_new_string(action));
            json_object_object_add(data, "control_revision", json_object_new_int64(revision + 1));
            json_object_object_add(data, "applied", json_object_new_boolean(1));
            json_object_object_add(data, "running", json_object_new_boolean(fs_control_running(service)));
            json_object_object_add(data, "enabled", json_object_new_boolean(autostart ? !strcmp(action, "enable") : before_enabled));
            response = fs_success(data); goto out;
        }
        rc = -1;
    }
    if (rc != 0) {
        int file_ok = !replaced || fs_snapshot_restore(config_path, &snapshot) == 0;
        int restored = file_ok && fs_service_action(script, autostart ? (before_enabled ? "enable" : "disable") : (before_running ? "restart" : "stop"), &restore) == 0;
        if (restored && !autostart && before_running && !strcmp(service, "nfs")) restored = fs_nfs_exports_apply(db, &restore) == 0;
        if (restored && !autostart && before_running) restored = fs_runtime_probe(db, service, &restore) == 0;
        if (restored && !autostart && !before_running) restored = !fs_control_running(service);
        if (restored && autostart) {
            int enabled = fs_service_action(script, "enabled", &restore);
            restored = (enabled == 0 || restore.exit_code == 1) && ((enabled == 0) == before_enabled);
        }
        int rolled_db = fs_sql_exec(db, "ROLLBACK") == 0; in_tx = 0;
        data = fs_error_detail("service_action_failed", result.timed_out ? "service_timeout" : "command_or_runtime_probe_failed");
        json_object_object_add(data, "service_action", json_object_new_string(action));
        json_object_object_add(data, "service_exit_code", json_object_new_int(result.exit_code));
        json_object_object_add(data, "rolled_back", json_object_new_boolean(restored && rolled_db));
        json_object_object_add(data, "rollback_failed", json_object_new_boolean(!restored || !rolled_db));
        json_object_object_add(data, "rollback_service_exit_code", json_object_new_int(restore.exit_code));
        json_object_object_add(data, "config_restored", json_object_new_boolean(file_ok));
        json_object_object_add(data, "db_rolled_back", json_object_new_boolean(rolled_db));
        json_object_object_add(data, "running", json_object_new_boolean(fs_control_running(service)));
        response = fs_envelope(FS_API_ERROR, data);
    }
out:
    if (in_tx) fs_sql_exec(db, "ROLLBACK");
    if (db) sqlite3_close(db);
    fs_buffer_free(&rendered);
    fs_snapshot_free(&snapshot);
    return response ? response : fs_error("storage_error", "service_control_failed");
}

struct json_object *jmx_samba_settings_set(struct json_object *req)
{
    struct json_object *payload = fs_payload(req), *response = NULL, *current = NULL, *value;
    struct fs_snapshot snapshot = {0};
    struct fs_exec_result result = {0};
    struct fs_buffer rendered = {0};
    sqlite3 *db = NULL;
    sqlite3_stmt *st = NULL;
    int present = 0, in_tx = 0, replaced = 0, was_running = 0;
    int64_t expected = 0, revision = 0;
    const char *reason = "", *action = "none";
    if (!fs_confirmed(req)) return fs_error("confirmation_required", "confirm_true_required");
    if (fs_json_positive_int64(payload, "expected_revision", &expected, &present) != 0 || !present)
        return fs_error("missing_expected_revision", "samba_settings_revision_required");
    json_object_object_foreach(payload, key, val) {
        (void)val;
        if (strcmp(key,"confirm") && strcmp(key,"apply") && strcmp(key,"expected_revision") &&
            strcmp(key,"workgroup") && strcmp(key,"server_description") && strcmp(key,"interfaces") &&
            (!fs_samba_extended_settings() || (strcmp(key,"min_protocol") && strcmp(key,"max_protocol") && strcmp(key,"guest_access"))))
            return fs_error("invalid_field", key);
    }
    if (fs_db_open(&db) != 0) return fs_error("storage_unavailable", "config_db_open_failed");
    if (fs_sql_exec(db,"BEGIN IMMEDIATE") != 0) goto out;
    in_tx = 1;
    current = fs_samba_get_data(db);
    json_object_object_get_ex(current,"revision",&value); revision = json_object_get_int64(value);
    if (revision != expected) { response = fs_revision_conflict("samba_settings_changed", expected, revision); goto out; }
    const char *keys[] = {"workgroup","server_description","interfaces"};
    for (size_t i=0; i<3; i++) if (json_object_object_get_ex(payload,keys[i],&value)) {
        if (i < 2) {
            const char *text = json_object_get_string(value);
            if (!json_object_is_type(value,json_type_string) || !fs_text_ok(text, i ? 128 : 15, 1) || strpbrk(text,"&#|\\'\"<>[]{};%?=")) {
                response = fs_error("invalid_settings",keys[i]); goto out;
            }
        } else {
            if (!json_object_is_type(value,json_type_array) || json_object_array_length(value)==0 || json_object_array_length(value)>16) {
                response = fs_error("invalid_interfaces","select_explicit_interfaces"); goto out;
            }
            for (size_t j=0;j<json_object_array_length(value);j++) {
                struct json_object *iface = json_object_array_get_idx(value,j);
                if (!json_object_is_type(iface,json_type_string) || !fs_id_ok(json_object_get_string(iface))) {
                    response = fs_error("invalid_interfaces","invalid_interface_name"); goto out;
                }
            }
        }
        json_object_object_add(current,keys[i],json_object_get(value));
    }
    const char *extended[] = {"min_protocol","max_protocol","guest_access"};
    for (int i=0; i<3; i++) if (json_object_object_get_ex(payload,extended[i],&value)) {
        if (i==2 ? !json_object_is_type(value,json_type_boolean) :
            (!json_object_is_type(value,json_type_string) || fs_smb_protocol_rank(json_object_get_string(value))<0)) {
            response=fs_error("invalid_settings",extended[i]); goto out;
        }
        json_object_object_add(current,extended[i],json_object_get(value));
    }
    struct json_object *min_version,*max_version;
    json_object_object_get_ex(current,"min_protocol",&min_version);
    json_object_object_get_ex(current,"max_protocol",&max_version);
    if(fs_smb_protocol_rank(json_object_get_string(min_version))>fs_smb_protocol_rank(json_object_get_string(max_version))) {
        response=fs_error("invalid_settings","min_protocol_exceeds_max_protocol");goto out;
    }
    if (json_object_object_get_ex(payload,"guest_access",&value) &&
        fs_sql_exec(db,"INSERT OR IGNORE INTO samba_service_policy VALUES(1)")!=0) goto out;
    if (fs_prepare(db,&st,"UPDATE samba_service SET workgroup=?1,server_description=?2,interfaces_json=?3,revision=revision+1,updated_at=?4,min_protocol=?6,max_protocol=?7,guest_access=?8 WHERE id=1 AND revision=?5") != 0) goto out;
    for(int i=0;i<3;i++) {
        json_object_object_get_ex(current,keys[i],&value);
        sqlite3_bind_text(st,i+1,i==2 ? json_object_to_json_string_ext(value,JSON_C_TO_STRING_PLAIN) : json_object_get_string(value),-1,SQLITE_TRANSIENT);
    }
    sqlite3_bind_int64(st,4,fs_now_s());sqlite3_bind_int64(st,5,expected);
    sqlite3_bind_text(st,6,json_object_get_string(min_version),-1,SQLITE_TRANSIENT);
    sqlite3_bind_text(st,7,json_object_get_string(max_version),-1,SQLITE_TRANSIENT);
    json_object_object_get_ex(current,"guest_access",&value);sqlite3_bind_int(st,8,json_object_get_boolean(value));
    if (fs_step_done(st) != 0 || sqlite3_changes(db) != 1) goto out;
    sqlite3_finalize(st);st=NULL;
    was_running=fs_control_running("samba");
    if (was_running) {
        if (fs_apply_new_config(db,"samba",&snapshot,&result,&action,&reason,&replaced) != 0) goto rollback;
    } else {
        if (fs_render_samba(db,&rendered)!=0 || fs_config_preflight("samba4",rendered.data,rendered.len)!=0) { reason="config_preflight_failed"; goto rollback; }
        if (fs_snapshot_read(JMX_SAMBA_CONFIG_PATH,&snapshot)!=0) { reason="snapshot_failed"; goto rollback; }
        if (fs_atomic_replace(JMX_SAMBA_CONFIG_PATH,rendered.data,rendered.len,snapshot.existed?snapshot.mode:0600)!=0) { reason="config_replace_failed"; goto rollback; }
        replaced=1;
    }
    fs_meta_bump(db);
    if (fs_sql_exec(db,"COMMIT")!=0) { reason="db_commit_failed"; goto rollback; }
    in_tx=0;
    struct json_object *data=json_object_new_object();
    json_object_object_add(data,"revision",json_object_new_int64(revision+1));
    json_object_object_add(data,"persisted",json_object_new_boolean(1));
    json_object_object_add(data,"applied",json_object_new_boolean(was_running));
    json_object_object_add(data,"service_action",json_object_new_string(action));
    json_object_object_add(data,"restart_required",json_object_new_boolean(!was_running));
    response=fs_success(data);goto out;
rollback:
    if (was_running) response=fs_apply_failure_rollback(db,"samba",&snapshot,replaced,"apply_failed",reason,&result);
    else {
        int file_ok=!replaced || fs_snapshot_restore(JMX_SAMBA_CONFIG_PATH,&snapshot)==0;
        int db_ok=fs_sql_exec(db,"ROLLBACK")==0;
        struct json_object *data=fs_error_detail("apply_failed",reason);
        json_object_object_add(data,"rolled_back",json_object_new_boolean(file_ok&&db_ok));
        json_object_object_add(data,"rollback_failed",json_object_new_boolean(!file_ok||!db_ok));
        response=fs_envelope(FS_API_ERROR,data);
    }
    in_tx=0;
out:
    if(st) sqlite3_finalize(st);
    if(in_tx) fs_sql_exec(db,"ROLLBACK");
    if(db) sqlite3_close(db);
    if(current) json_object_put(current);
    fs_snapshot_free(&snapshot);fs_buffer_free(&rendered);
    return response?response:fs_error("storage_error","samba_settings_failed");
}

#include "file_service_accounts.inc"

#include "file_service_operations.inc"

#include "file_service_webdav.inc"

#include "file_service_defaults.inc"

#include "file_service_bindings.inc"

#include "file_service_ftp.inc"
