// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * jmx_gateway_shadow.c - Gateway Shadow (VRRP HA) control plane
 *
 * The first implementation deliberately separates draft persistence from
 * activation.  A valid local draft is useful to the web pairing wizard, but
 * keepalived must never be started until a mutually authenticated peer exists.
 */
#include "jmx_gateway_shadow.h"
#include "jmx_gateway_shadow_pairing.h"
#include "jmx_gateway_shadow_runtime.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <limits.h>
#include <signal.h>
#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define API_CODE_SUCCESS 2000
#define API_CODE_ERROR 4000
extern struct json_object *jmx_gen_api_response_data(int code,
                                                     struct json_object *data_obj);

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define GS_DB_PATH "/etc/dreamingwrt/config.db"
#define GS_RUNTIME_DIR "/etc/dreamingwrt/gateway-shadow"
#define GS_AUTH_KEY_PATH "/etc/dreamingwrt/gateway-shadow/auth.key"
/*
 * These must match the Shadow-owned paths written by
 * jmx_gateway_shadow_runtime.c, not the distribution-wide keepalived
 * pidfile; otherwise status would report an unrelated instance.
 */
#define GS_KEEPALIVED_PID \
    "/var/run/dreamingwrt-gateway-shadow-keepalived.pid"
#define GS_CONNTRACKD_CTL \
    "/var/run/dreamingwrt-gateway-shadow-conntrackd.ctl"

static const char *gs_db_path(void)
{
    const char *override = getenv("DREAMINGWRT_CONFIG_DB");
    return override && override[0] ? override : GS_DB_PATH;
}

static const char *gs_runtime_dir(void)
{
    const char *override = getenv("DREAMINGWRT_GATEWAY_SHADOW_DIR");
    return override && override[0] ? override : GS_RUNTIME_DIR;
}

static int gs_auth_key_path(char *out, size_t out_len)
{
    int count;
    if (!out || out_len < 2) return -1;
    count = snprintf(out, out_len, "%s/auth.key", gs_runtime_dir());
    return count > 0 && (size_t)count < out_len ? 0 : -1;
}

static int64_t gs_now(void)
{
    return (int64_t)time(NULL);
}

static int gs_open(sqlite3 **db)
{
    if (!db || sqlite3_open_v2(gs_db_path(), db,
                               SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE,
                               NULL) != SQLITE_OK) {
        if (db && *db) { sqlite3_close(*db); *db = NULL; }
        return -1;
    }
    sqlite3_busy_timeout(*db, 3000);
    return 0;
}

static int gs_exec(sqlite3 *db, const char *sql)
{
    char *error = NULL;
    int rc;

    if (!db || !sql) return -1;
    rc = sqlite3_exec(db, sql, NULL, NULL, &error);
    if (error) sqlite3_free(error);
    return rc == SQLITE_OK ? 0 : -1;
}

int jmx_gateway_shadow_schema_ensure(void)
{
    sqlite3 *db = NULL;
    const char *sql =
        "CREATE TABLE IF NOT EXISTS gateway_shadow_config ("
        " id INTEGER PRIMARY KEY CHECK(id=1),"
        " enabled INTEGER NOT NULL DEFAULT 0 CHECK(enabled IN (0,1)),"
        " role TEXT NOT NULL DEFAULT 'primary' CHECK(role IN ('primary','secondary')),"
        " lan_interface TEXT NOT NULL DEFAULT 'br-lan',"
        " management_ipv4 TEXT NOT NULL DEFAULT '',"
        " heartbeat_interface TEXT NOT NULL DEFAULT '',"
        " heartbeat_local_ip TEXT NOT NULL DEFAULT '',"
        " heartbeat_peer_ip TEXT NOT NULL DEFAULT '',"
        " heartbeat_prefix_length INTEGER NOT NULL DEFAULT 30 CHECK(heartbeat_prefix_length BETWEEN 1 AND 32),"
        " virtual_ipv4 TEXT NOT NULL DEFAULT '',"
        " virtual_router_id INTEGER NOT NULL DEFAULT 51 CHECK(virtual_router_id BETWEEN 1 AND 255),"
        " priority INTEGER NOT NULL DEFAULT 150 CHECK(priority BETWEEN 1 AND 254),"
        " advert_interval_seconds INTEGER NOT NULL DEFAULT 1 CHECK(advert_interval_seconds BETWEEN 1 AND 60),"
        " preempt INTEGER NOT NULL DEFAULT 0 CHECK(preempt IN (0,1)),"
        " connection_sync INTEGER NOT NULL DEFAULT 1 CHECK(connection_sync IN (0,1)),"
        " revision INTEGER NOT NULL DEFAULT 0,"
        " updated_at INTEGER NOT NULL DEFAULT 0);"
        "INSERT OR IGNORE INTO gateway_shadow_config(id) VALUES(1);"
        "CREATE TABLE IF NOT EXISTS gateway_shadow_peer ("
        " id INTEGER PRIMARY KEY CHECK(id=1),"
        " peer_id TEXT NOT NULL DEFAULT '',"
        " certificate_fingerprint TEXT NOT NULL DEFAULT '',"
        " trust_state TEXT NOT NULL DEFAULT 'unpaired'"
        "   CHECK(trust_state IN ('unpaired','pending','paired','revoked')),"
        " management_address TEXT NOT NULL DEFAULT '',"
        " last_seen_at INTEGER NOT NULL DEFAULT 0,"
        " updated_at INTEGER NOT NULL DEFAULT 0);"
        "INSERT OR IGNORE INTO gateway_shadow_peer(id) VALUES(1);"
        "CREATE TABLE IF NOT EXISTS gateway_shadow_runtime ("
        " id INTEGER PRIMARY KEY CHECK(id=1),"
        " state TEXT NOT NULL DEFAULT 'inactive',"
        " vrrp_state TEXT NOT NULL DEFAULT 'unknown',"
        " last_transition_at INTEGER NOT NULL DEFAULT 0,"
        " last_apply_at INTEGER NOT NULL DEFAULT 0,"
        " last_error TEXT NOT NULL DEFAULT '',"
        " managed_daemons INTEGER NOT NULL DEFAULT 0 CHECK(managed_daemons IN (0,1)),"
        " updated_at INTEGER NOT NULL DEFAULT 0);"
        "INSERT OR IGNORE INTO gateway_shadow_runtime(id) VALUES(1);";
    int rc;

    if (gs_open(&db) != 0) return -1;
    rc = gs_exec(db, sql);
    if (rc == 0) {
        /* Existing config.db instances predate these topology-safety fields. */
        sqlite3_stmt *st = NULL;
        int have_management = 0, have_heartbeat_prefix = 0;
        if (sqlite3_prepare_v2(db, "PRAGMA table_info(gateway_shadow_config)",
                               -1, &st, NULL) == SQLITE_OK) {
            while (sqlite3_step(st) == SQLITE_ROW) {
                const char *name = (const char *)sqlite3_column_text(st, 1);
                if (name && !strcmp(name, "management_ipv4")) have_management = 1;
                if (name && !strcmp(name, "heartbeat_prefix_length")) have_heartbeat_prefix = 1;
            }
        }
        if (st) sqlite3_finalize(st);
        if (!have_management &&
            gs_exec(db, "ALTER TABLE gateway_shadow_config ADD COLUMN management_ipv4 TEXT NOT NULL DEFAULT ''") != 0) rc = -1;
        if (!have_heartbeat_prefix &&
            gs_exec(db, "ALTER TABLE gateway_shadow_config ADD COLUMN heartbeat_prefix_length INTEGER NOT NULL DEFAULT 30") != 0) rc = -1;
    }
    sqlite3_close(db);
    return rc;
}

static void gs_add_string(struct json_object *obj, const char *key, const char *value)
{
    json_object_object_add(obj, key, json_object_new_string(value ? value : ""));
}

static struct json_object *gs_response(int ok, struct json_object *data, const char *error)
{
    if (!data) data = json_object_new_object();
    json_object_object_add(data, "ok", json_object_new_boolean(ok));
    if (!ok && error && error[0]) gs_add_string(data, "error", error);
    return jmx_gen_api_response_data(ok ? API_CODE_SUCCESS : API_CODE_ERROR, data);
}

static const char *gs_sql_text(sqlite3_stmt *st, int column)
{
    const unsigned char *value = sqlite3_column_text(st, column);
    return value ? (const char *)value : "";
}

static struct json_object *gs_config_read(sqlite3 *db)
{
    sqlite3_stmt *st = NULL;
    struct json_object *cfg = json_object_new_object();
    const char *sql =
        "SELECT enabled,role,lan_interface,management_ipv4,heartbeat_interface,"
        "heartbeat_local_ip,heartbeat_peer_ip,heartbeat_prefix_length,virtual_ipv4,virtual_router_id,"
        "priority,advert_interval_seconds,preempt,connection_sync,revision,updated_at "
        "FROM gateway_shadow_config WHERE id=1";

    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK ||
        sqlite3_step(st) != SQLITE_ROW) {
        if (st) sqlite3_finalize(st);
        json_object_put(cfg);
        return NULL;
    }
    json_object_object_add(cfg, "enabled", json_object_new_boolean(sqlite3_column_int(st, 0)));
    gs_add_string(cfg, "role", gs_sql_text(st, 1));
    gs_add_string(cfg, "lan_interface", gs_sql_text(st, 2));
    gs_add_string(cfg, "management_ipv4", gs_sql_text(st, 3));
    gs_add_string(cfg, "heartbeat_interface", gs_sql_text(st, 4));
    gs_add_string(cfg, "heartbeat_local_ip", gs_sql_text(st, 5));
    gs_add_string(cfg, "heartbeat_peer_ip", gs_sql_text(st, 6));
    json_object_object_add(cfg, "heartbeat_prefix_length", json_object_new_int(sqlite3_column_int(st, 7)));
    gs_add_string(cfg, "virtual_ipv4", gs_sql_text(st, 8));
    json_object_object_add(cfg, "virtual_router_id", json_object_new_int(sqlite3_column_int(st, 9)));
    json_object_object_add(cfg, "priority", json_object_new_int(sqlite3_column_int(st, 10)));
    json_object_object_add(cfg, "advert_interval_seconds", json_object_new_int(sqlite3_column_int(st, 11)));
    json_object_object_add(cfg, "preempt", json_object_new_boolean(sqlite3_column_int(st, 12)));
    json_object_object_add(cfg, "connection_sync", json_object_new_boolean(sqlite3_column_int(st, 13)));
    json_object_object_add(cfg, "revision", json_object_new_int64(sqlite3_column_int64(st, 14)));
    json_object_object_add(cfg, "updated_at", json_object_new_int64(sqlite3_column_int64(st, 15)));
    sqlite3_finalize(st);
    return cfg;
}

static struct json_object *gs_peer_read(sqlite3 *db)
{
    sqlite3_stmt *st = NULL;
    struct json_object *peer = json_object_new_object();
    const char *sql = "SELECT peer_id,certificate_fingerprint,trust_state,"
                      "management_address,last_seen_at,updated_at "
                      "FROM gateway_shadow_peer WHERE id=1";

    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK ||
        sqlite3_step(st) != SQLITE_ROW) {
        if (st) sqlite3_finalize(st);
        json_object_put(peer);
        return NULL;
    }
    gs_add_string(peer, "peer_id", gs_sql_text(st, 0));
    gs_add_string(peer, "certificate_fingerprint", gs_sql_text(st, 1));
    gs_add_string(peer, "trust_state", gs_sql_text(st, 2));
    gs_add_string(peer, "management_address", gs_sql_text(st, 3));
    json_object_object_add(peer, "last_seen_at", json_object_new_int64(sqlite3_column_int64(st, 4)));
    json_object_object_add(peer, "updated_at", json_object_new_int64(sqlite3_column_int64(st, 5)));
    sqlite3_finalize(st);
    return peer;
}

static int gs_safe_ifname(const char *name)
{
    size_t i, length;
    if (!name || !(length = strlen(name)) || length >= 64) return 0;
    for (i = 0; i < length; i++)
        if (!isalnum((unsigned char)name[i]) && name[i] != '_' && name[i] != '-' &&
            name[i] != '.' && name[i] != ':') return 0;
    return 1;
}

static int gs_ipv4(const char *text)
{
    struct in_addr address;
    return text && inet_pton(AF_INET, text, &address) == 1;
}

/*
 * The runtime module requires heartbeat addresses inside the dedicated,
 * non-routed 169.254/16 link-local range, excluding network and broadcast.
 * Mirror that here so a draft that can never be applied is refused at save.
 */
static int gs_heartbeat_ipv4(const char *text)
{
    struct in_addr address;
    uint32_t host;
    if (!text || inet_pton(AF_INET, text, &address) != 1) return 0;
    host = ntohl(address.s_addr);
    return (host & 0xffff0000U) == 0xa9fe0000U &&
           (host & 0x0000ffffU) != 0 && (host & 0x0000ffffU) != 0xffffU;
}

/* Mirror gs_virtual_ipv4(): reject 0.0.0.0, loopback, multicast, broadcast. */
static int gs_usable_virtual_ipv4(const char *text)
{
    struct in_addr address;
    char copy[64];
    const char *slash;
    size_t length;
    uint32_t host;
    if (!text || !(slash = strrchr(text, '/'))) return 0;
    length = (size_t)(slash - text);
    if (!length || length >= sizeof(copy)) return 0;
    memcpy(copy, text, length); copy[length] = '\0';
    if (inet_pton(AF_INET, copy, &address) != 1) return 0;
    host = ntohl(address.s_addr);
    return host != 0 && (host & 0xff000000U) != 0x7f000000U &&
           (host & 0xf0000000U) != 0xe0000000U && host != 0xffffffffU;
}

static int gs_ipv4_cidr(const char *text)
{
    char address[64];
    const char *slash;
    char *end = NULL;
    long prefix;
    size_t length;

    if (!text || !(slash = strrchr(text, '/'))) return 0;
    length = (size_t)(slash - text);
    if (!length || length >= sizeof(address)) return 0;
    memcpy(address, text, length); address[length] = '\0';
    errno = 0; prefix = strtol(slash + 1, &end, 10);
    return !errno && end && !*end && prefix >= 1 && prefix <= 32 && gs_ipv4(address);
}

static int gs_cidr_address(const char *cidr, char *out, size_t out_len)
{
    const char *slash;
    size_t length;
    if (!cidr || !out || out_len < 2 || !(slash = strchr(cidr, '/'))) return -1;
    length = (size_t)(slash - cidr);
    if (!length || length >= out_len) return -1;
    memcpy(out, cidr, length); out[length] = '\0';
    return gs_ipv4(out) ? 0 : -1;
}

static int gs_same_ipv4_subnet(const char *left, const char *right, int prefix)
{
    struct in_addr a, b;
    uint32_t mask;
    if (!gs_ipv4(left) || !gs_ipv4(right) || prefix < 1 || prefix > 32) return 0;
    inet_pton(AF_INET, left, &a); inet_pton(AF_INET, right, &b);
    mask = prefix == 32 ? UINT32_MAX : htonl(UINT32_MAX << (32 - prefix));
    return (a.s_addr & mask) == (b.s_addr & mask);
}

static int gs_interface_exists(const char *name)
{
    char path[128];
    if (!gs_safe_ifname(name)) return 0;
    snprintf(path, sizeof(path), "/sys/class/net/%s", name);
    return access(path, F_OK) == 0;
}

static int gs_binary_path(const char *name, char *out, size_t out_len)
{
    static const char *dirs[] = { "/usr/sbin", "/usr/bin", "/sbin", "/bin" };
    size_t i;
    if (!name || !name[0] || !out || out_len < 2) return 0;
    for (i = 0; i < sizeof(dirs) / sizeof(dirs[0]); i++) {
        int count = snprintf(out, out_len, "%s/%s", dirs[i], name);
        if (count <= 0 || (size_t)count >= out_len) continue;
        if (access(out, X_OK) == 0) return 1;
    }
    out[0] = '\0';
    return 0;
}

static int gs_binary_exists(const char *name)
{
    char path[PATH_MAX];
    return gs_binary_path(name, path, sizeof(path));
}

/*
 * conntrackd has no pidfile.  The Shadow configuration pins a UNIX control
 * socket, so its presence is the honest liveness signal for our instance.
 */
static int gs_conntrackd_running(void)
{
    struct stat status;
    return lstat(GS_CONNTRACKD_CTL, &status) == 0 && S_ISSOCK(status.st_mode);
}

static const char *gs_json_string(struct json_object *obj, const char *key, const char *fallback)
{
    struct json_object *value = NULL;
    const char *text;
    if (!obj || !json_object_object_get_ex(obj, key, &value) || !value ||
        !json_object_is_type(value, json_type_string)) return fallback;
    text = json_object_get_string(value);
    return text ? text : fallback;
}

static int gs_json_int(struct json_object *obj, const char *key, int fallback)
{
    struct json_object *value = NULL;
    return obj && json_object_object_get_ex(obj, key, &value) && value ?
           json_object_get_int(value) : fallback;
}

static int gs_json_bool(struct json_object *obj, const char *key, int fallback)
{
    struct json_object *value = NULL;
    return obj && json_object_object_get_ex(obj, key, &value) && value ?
           json_object_get_boolean(value) : fallback;
}

static struct json_object *gs_payload_config(struct json_object *payload)
{
    struct json_object *cfg = NULL;
    if (payload && json_object_object_get_ex(payload, "config", &cfg) && cfg &&
        json_object_is_type(cfg, json_type_object)) return cfg;
    return payload;
}

static int gs_validate(struct json_object *cfg, struct json_object *errors)
{
    const char *role = gs_json_string(cfg, "role", "");
    const char *lan = gs_json_string(cfg, "lan_interface", "");
    const char *management = gs_json_string(cfg, "management_ipv4", "");
    const char *heartbeat = gs_json_string(cfg, "heartbeat_interface", "");
    const char *local = gs_json_string(cfg, "heartbeat_local_ip", "");
    const char *peer = gs_json_string(cfg, "heartbeat_peer_ip", "");
    const char *vip = gs_json_string(cfg, "virtual_ipv4", "");
    int heartbeat_prefix = gs_json_int(cfg, "heartbeat_prefix_length", 0);
    int vrid = gs_json_int(cfg, "virtual_router_id", 0);
    int priority = gs_json_int(cfg, "priority", 0);
    int advert = gs_json_int(cfg, "advert_interval_seconds", 0);
    char management_address[64] = "", vip_address[64] = "";
    char vip_only[64] = "";

    (void)gs_cidr_address(vip, vip_only, sizeof(vip_only));

#define GS_ERR(code) json_object_array_add(errors, json_object_new_string(code))
    if (strcmp(role, "primary") && strcmp(role, "secondary")) GS_ERR("role_invalid");
    if (!gs_safe_ifname(lan)) GS_ERR("lan_interface_invalid");
    if (!gs_ipv4_cidr(management)) GS_ERR("management_ipv4_invalid");
    if (!gs_safe_ifname(heartbeat)) GS_ERR("heartbeat_interface_invalid");
    if (lan[0] && heartbeat[0] && !strcmp(lan, heartbeat)) GS_ERR("heartbeat_interface_must_be_dedicated");
    if (!gs_heartbeat_ipv4(local)) GS_ERR("heartbeat_local_ip_invalid");
    if (!gs_heartbeat_ipv4(peer)) GS_ERR("heartbeat_peer_ip_invalid");
    if (heartbeat_prefix < 1 || heartbeat_prefix > 32) GS_ERR("heartbeat_prefix_length_invalid");
    else if (gs_ipv4(local) && gs_ipv4(peer) &&
             !gs_same_ipv4_subnet(local, peer, heartbeat_prefix)) GS_ERR("heartbeat_addresses_not_same_subnet");
    if (local[0] && peer[0] && !strcmp(local, peer)) GS_ERR("heartbeat_addresses_must_differ");
    if (!gs_ipv4_cidr(vip) || !gs_usable_virtual_ipv4(vip)) GS_ERR("virtual_ipv4_invalid");
    if (gs_usable_virtual_ipv4(vip) &&
        (!strcmp(vip_only, local) || !strcmp(vip_only, peer)))
        GS_ERR("virtual_ipv4_conflicts_with_heartbeat");
    /*
     * Phase one renders "nopreempt" unconditionally and the runtime validator
     * refuses preempt, so accepting it here would produce a draft that can be
     * saved but never applied.
     */
    if (gs_json_bool(cfg, "preempt", 0)) GS_ERR("preempt_unsupported");
    if (gs_cidr_address(management, management_address, sizeof(management_address)) == 0 &&
        gs_cidr_address(vip, vip_address, sizeof(vip_address)) == 0 &&
        !strcmp(management_address, vip_address)) GS_ERR("management_ipv4_conflicts_with_virtual_ipv4");
    if (vrid < 1 || vrid > 255) GS_ERR("virtual_router_id_invalid");
    if (priority < 1 || priority > 254) GS_ERR("priority_invalid");
    if (advert < 1 || advert > 60) GS_ERR("advert_interval_invalid");
#undef GS_ERR
    return json_object_array_length(errors) == 0 ? 0 : -1;
}

static int gs_peer_paired(struct json_object *peer)
{
    return peer && !strcmp(gs_json_string(peer, "trust_state", "unpaired"), "paired") &&
           gs_json_string(peer, "peer_id", "")[0] &&
           gs_json_string(peer, "certificate_fingerprint", "")[0];
}

/*
 * Every capability bit below is a runtime probe, never a literal.  Pairing is
 * implemented in jmx_gateway_shadow_pairing.c and only needs libcrypto plus
 * writable state, so it is advertised independently of keepalived.  Apply
 * additionally needs a mutually authenticated peer and a real keepalived
 * binary, because that is where VRRP is actually started.
 */
static struct json_object *gs_capabilities(int keepalived, int conntrackd, int paired)
{
    struct json_object *cap = json_object_new_object();
    int pairing = jmx_gateway_shadow_pairing_available();
    json_object_object_add(cap, "read", json_object_new_boolean(1));
    json_object_object_add(cap, "save", json_object_new_boolean(1));
    json_object_object_add(cap, "preflight", json_object_new_boolean(1));
    json_object_object_add(cap, "status", json_object_new_boolean(1));
    json_object_object_add(cap, "pairing_supported", json_object_new_boolean(pairing));
    json_object_object_add(cap, "apply_supported",
                           json_object_new_boolean(paired && keepalived));
    json_object_object_add(cap, "disable_supported", json_object_new_boolean(1));
    json_object_object_add(cap, "vrrp_supported", json_object_new_boolean(keepalived));
    json_object_object_add(cap, "connection_sync_supported", json_object_new_boolean(conntrackd));
    json_object_object_add(cap, "secrets_write_only", json_object_new_boolean(1));
    json_object_object_add(cap, "session_continuity", json_object_new_string("best_effort"));
    if (!pairing) gs_add_string(cap, "reason", "pairing_runtime_unavailable");
    else if (!paired) gs_add_string(cap, "reason", "mutual_authenticated_peer_pairing_pending");
    else if (!keepalived) gs_add_string(cap, "reason", "keepalived_not_installed");
    return cap;
}

static int gs_write_all(int fd, const char *buffer, size_t length)
{
    size_t offset = 0;
    while (offset < length) {
        ssize_t count = write(fd, buffer + offset, length - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return -1;
        offset += (size_t)count;
    }
    return 0;
}

/* Secret staging is atomic and never puts the value in argv, logs or JSON. */
static int gs_auth_key_write_atomic(const char *secret)
{
    char temporary[256];
    char auth_key_path[256];
    const char *runtime_dir = gs_runtime_dir();
    int fd = -1, directory_fd = -1;
    size_t length;
    int rc = -1;

    if (!secret || (length = strlen(secret)) < 16 || length > 128 ||
        gs_auth_key_path(auth_key_path, sizeof(auth_key_path)) != 0)
        return -1;
    if (!getenv("DREAMINGWRT_GATEWAY_SHADOW_DIR") &&
        mkdir("/etc/dreamingwrt", 0700) != 0 && errno != EEXIST)
        return -1;
    if (mkdir(runtime_dir, 0700) != 0 && errno != EEXIST)
        return -1;
    if (chmod(runtime_dir, 0700) != 0)
        return -1;
    snprintf(temporary, sizeof(temporary), "%s/.auth.key.tmp.%ld",
             runtime_dir, (long)getpid());
    fd = open(temporary, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0) return -1;
    if (fchmod(fd, S_IRUSR | S_IWUSR) != 0 ||
        gs_write_all(fd, secret, length) != 0 ||
        gs_write_all(fd, "\n", 1) != 0 || fsync(fd) != 0)
        goto done;
    if (close(fd) != 0) { fd = -1; goto done; }
    fd = -1;
    if (rename(temporary, auth_key_path) != 0 || chmod(auth_key_path, 0600) != 0)
        goto done;
    directory_fd = open(runtime_dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (directory_fd >= 0 && fsync(directory_fd) != 0) goto done;
    rc = 0;
done:
    if (fd >= 0) close(fd);
    if (directory_fd >= 0) close(directory_fd);
    if (rc != 0) unlink(temporary);
    return rc;
}

static int gs_auth_key_snapshot(char *out, size_t out_len)
{
    char path[256];
    FILE *stream;
    size_t length;
    if (!out || out_len < 2 || gs_auth_key_path(path, sizeof(path)) != 0) return -1;
    out[0] = '\0';
    stream = fopen(path, "r");
    if (!stream) return errno == ENOENT ? 0 : -1;
    if (!fgets(out, (int)out_len, stream) && ferror(stream)) { fclose(stream); return -1; }
    if (fclose(stream) != 0) return -1;
    length = strlen(out);
    while (length && (out[length - 1] == '\n' || out[length - 1] == '\r')) out[--length] = '\0';
    return length ? 1 : 0;
}

static void gs_auth_key_restore(const char *old_secret, int old_present)
{
    char path[256];
    if (old_present > 0 && old_secret && old_secret[0]) {
        (void)gs_auth_key_write_atomic(old_secret);
    } else if (gs_auth_key_path(path, sizeof(path)) == 0) {
        (void)unlink(path);
    }
}

struct json_object *jmx_gateway_shadow_get(void)
{
    sqlite3 *db = NULL;
    struct json_object *data, *cfg, *peer;
    int keepalived, conntrackd, paired;

    if (jmx_gateway_shadow_schema_ensure() != 0 || gs_open(&db) != 0)
        return gs_response(0, NULL, "gateway_shadow_storage_unavailable");
    cfg = gs_config_read(db); peer = gs_peer_read(db); sqlite3_close(db);
    if (!cfg || !peer) {
        if (cfg) json_object_put(cfg); if (peer) json_object_put(peer);
        return gs_response(0, NULL, "gateway_shadow_read_failed");
    }
    keepalived = gs_binary_exists("keepalived");
    conntrackd = gs_binary_exists("conntrackd");
    paired = gs_peer_paired(peer);
    data = json_object_new_object();
    json_object_object_add(data, "config", cfg);
    json_object_object_add(data, "peer", peer);
    json_object_object_add(data, "capabilities", gs_capabilities(keepalived, conntrackd, paired));
    return gs_response(1, data, NULL);
}

static int gs_pid_alive(const char *path)
{
    FILE *stream = fopen(path, "r");
    long pid = 0;
    if (!stream) return 0;
    if (fscanf(stream, "%ld", &pid) != 1) pid = 0;
    fclose(stream);
    return pid > 1 && kill((pid_t)pid, 0) == 0;
}

static int gs_virtual_ip_present(const char *ifname, const char *cidr)
{
    struct ifaddrs *list = NULL, *item;
    char expected[64], current[INET_ADDRSTRLEN];
    const char *slash;
    size_t length;
    int found = 0;

    if (!ifname || !cidr || !(slash = strchr(cidr, '/'))) return 0;
    length = (size_t)(slash - cidr);
    if (!length || length >= sizeof(expected)) return 0;
    memcpy(expected, cidr, length); expected[length] = '\0';
    if (getifaddrs(&list) != 0) return 0;
    for (item = list; item; item = item->ifa_next) {
        if (!item->ifa_addr || item->ifa_addr->sa_family != AF_INET ||
            strcmp(item->ifa_name, ifname)) continue;
        if (inet_ntop(AF_INET, &((struct sockaddr_in *)item->ifa_addr)->sin_addr,
                      current, sizeof(current)) && !strcmp(current, expected)) { found = 1; break; }
    }
    freeifaddrs(list);
    return found;
}

struct json_object *jmx_gateway_shadow_status(void)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *st = NULL;
    struct json_object *data = json_object_new_object(), *cfg = NULL, *peer = NULL;
    int keepalived = gs_binary_exists("keepalived");
    int conntrackd = gs_binary_exists("conntrackd");

    if (jmx_gateway_shadow_schema_ensure() != 0 || gs_open(&db) != 0) {
        json_object_put(data);
        return gs_response(0, NULL, "gateway_shadow_storage_unavailable");
    }
    cfg = gs_config_read(db); peer = gs_peer_read(db);
    if (sqlite3_prepare_v2(db, "SELECT state,vrrp_state,last_transition_at,last_apply_at,"
                              "last_error,managed_daemons,updated_at FROM gateway_shadow_runtime WHERE id=1",
                           -1, &st, NULL) == SQLITE_OK && sqlite3_step(st) == SQLITE_ROW) {
        gs_add_string(data, "state", gs_sql_text(st, 0));
        gs_add_string(data, "vrrp_state", gs_sql_text(st, 1));
        json_object_object_add(data, "last_transition_at", json_object_new_int64(sqlite3_column_int64(st, 2)));
        json_object_object_add(data, "last_apply_at", json_object_new_int64(sqlite3_column_int64(st, 3)));
        gs_add_string(data, "last_error", gs_sql_text(st, 4));
        json_object_object_add(data, "managed_daemons", json_object_new_boolean(sqlite3_column_int(st, 5)));
        json_object_object_add(data, "updated_at", json_object_new_int64(sqlite3_column_int64(st, 6)));
    } else {
        gs_add_string(data, "state", "unknown");
        gs_add_string(data, "vrrp_state", "unknown");
    }
    if (st) sqlite3_finalize(st);
    sqlite3_close(db);
    json_object_object_add(data, "enabled", json_object_new_boolean(
        cfg ? gs_json_bool(cfg, "enabled", 0) : 0));
    gs_add_string(data, "configured_role",
                  cfg ? gs_json_string(cfg, "role", "primary") : "unknown");
    gs_add_string(data, "runtime_role", "disabled");
    json_object_object_add(data, "paired", json_object_new_boolean(gs_peer_paired(peer)));
    json_object_object_add(data, "peer_reachable", NULL);
    json_object_object_add(data, "keepalived_available", json_object_new_boolean(keepalived));
    json_object_object_add(data, "keepalived_running", json_object_new_boolean(gs_pid_alive(GS_KEEPALIVED_PID)));
    json_object_object_add(data, "conntrackd_available", json_object_new_boolean(conntrackd));
    json_object_object_add(data, "conntrackd_running",
                           json_object_new_boolean(gs_conntrackd_running()));
    json_object_object_add(data, "virtual_ipv4_present", json_object_new_boolean(
        cfg ? gs_virtual_ip_present(gs_json_string(cfg, "lan_interface", ""),
                                    gs_json_string(cfg, "virtual_ipv4", "")) : 0));
    gs_add_string(data, "session_continuity", "best_effort");
    json_object_object_add(data, "capabilities", gs_capabilities(keepalived, conntrackd, gs_peer_paired(peer)));
    if (cfg) json_object_put(cfg); if (peer) json_object_put(peer);
    return gs_response(1, data, NULL);
}

static void gs_check_add(struct json_object *checks, const char *name, int passed, const char *reason)
{
    struct json_object *check = json_object_new_object();
    gs_add_string(check, "name", name);
    json_object_object_add(check, "passed", json_object_new_boolean(passed));
    if (!passed && reason) gs_add_string(check, "reason", reason);
    json_object_array_add(checks, check);
}

struct json_object *jmx_gateway_shadow_preflight(struct json_object *payload)
{
    sqlite3 *db = NULL;
    struct json_object *cfg = NULL, *peer = NULL, *errors = json_object_new_array();
    struct json_object *checks = json_object_new_array(), *data = json_object_new_object();
    int keepalived, conntrackd, paired, valid, ready;

    if (jmx_gateway_shadow_schema_ensure() != 0 || gs_open(&db) != 0) {
        json_object_put(errors); json_object_put(checks); json_object_put(data);
        return gs_response(0, NULL, "gateway_shadow_storage_unavailable");
    }
    cfg = payload && json_object_is_type(gs_payload_config(payload), json_type_object) ?
          json_object_get(gs_payload_config(payload)) : gs_config_read(db);
    peer = gs_peer_read(db); sqlite3_close(db);
    if (!cfg || !peer) {
        if (cfg) json_object_put(cfg); if (peer) json_object_put(peer);
        json_object_put(errors); json_object_put(checks); json_object_put(data);
        return gs_response(0, NULL, "gateway_shadow_read_failed");
    }
    valid = gs_validate(cfg, errors) == 0;
    keepalived = gs_binary_exists("keepalived");
    conntrackd = gs_binary_exists("conntrackd");
    paired = gs_peer_paired(peer);
    gs_check_add(checks, "configuration", valid, "configuration_invalid");
    gs_check_add(checks, "lan_interface", gs_interface_exists(gs_json_string(cfg, "lan_interface", "")), "lan_interface_not_found");
    gs_check_add(checks, "heartbeat_interface", gs_interface_exists(gs_json_string(cfg, "heartbeat_interface", "")), "heartbeat_interface_not_found");
    gs_check_add(checks, "keepalived", keepalived, "keepalived_not_installed");
    gs_check_add(checks, "conntrackd", !gs_json_bool(cfg, "connection_sync", 1) || conntrackd, "conntrackd_not_installed");
    gs_check_add(checks, "mutual_peer_trust", paired, "mutual_authenticated_peer_pairing_pending");
    /*
     * Real readiness.  Phase one still requires a mutually authenticated peer
     * before keepalived may be started, so pairing is one term of the
     * conjunction rather than a hard-coded blocker.
     */
    ready = valid && paired && keepalived &&
            gs_interface_exists(gs_json_string(cfg, "lan_interface", "")) &&
            gs_interface_exists(gs_json_string(cfg, "heartbeat_interface", "")) &&
            (!gs_json_bool(cfg, "connection_sync", 1) || conntrackd);
    json_object_object_add(data, "ready", json_object_new_boolean(ready));
    json_object_object_add(data, "checks", checks);
    json_object_object_add(data, "errors", errors);
    json_object_object_add(data, "capabilities", gs_capabilities(keepalived, conntrackd, paired));
    if (!ready)
        gs_add_string(data, "reason",
                      !paired ? "mutual_authenticated_peer_pairing_pending" :
                      !keepalived ? "keepalived_not_installed" :
                      !valid ? "configuration_invalid" : "preflight_failed");
    json_object_put(cfg); json_object_put(peer);
    return gs_response(1, data, NULL);
}

struct json_object *jmx_gateway_shadow_save(struct json_object *payload)
{
    sqlite3 *db = NULL; sqlite3_stmt *st = NULL;
    struct json_object *cfg = gs_payload_config(payload), *errors = json_object_new_array();
    struct json_object *data = json_object_new_object();
    struct json_object *secret_value = NULL;
    const char *auth_key = NULL;
    int secret_supplied = 0;
    char auth_key_path[256] = "";
    char old_auth_key[130] = "";
    int old_auth_key_present = 0;
    int transaction_started = 0;
    const char *sql =
        "UPDATE gateway_shadow_config SET enabled=?1,role=?2,lan_interface=?3,management_ipv4=?4,"
        "heartbeat_interface=?5,heartbeat_local_ip=?6,heartbeat_peer_ip=?7,heartbeat_prefix_length=?8,virtual_ipv4=?9,"
        "virtual_router_id=?10,priority=?11,advert_interval_seconds=?12,preempt=?13,"
        "connection_sync=?14,revision=revision+1,updated_at=?15 WHERE id=1";
    int rc = -1;

    if (!cfg || !json_object_is_type(cfg, json_type_object)) {
        json_object_put(errors); json_object_put(data);
        return gs_response(0, NULL, "invalid_json");
    }
    /* auth_key is a write-only input: it is never copied into a response/table. */
    if (json_object_object_get_ex(cfg, "auth_key", &secret_value)) {
        secret_supplied = 1;
        if (!secret_value || !json_object_is_type(secret_value, json_type_string) ||
            !(auth_key = json_object_get_string(secret_value)) ||
            strlen(auth_key) < 16 || strlen(auth_key) > 128) {
            json_object_put(errors); json_object_put(data);
            return gs_response(0, NULL, "auth_key_invalid");
        }
    }
    if (gs_validate(cfg, errors) != 0) {
        json_object_object_add(data, "errors", errors);
        return gs_response(0, data, "validation_failed");
    }
    json_object_put(errors);
    if (jmx_gateway_shadow_schema_ensure() != 0 || gs_open(&db) != 0) {
        json_object_put(data); return gs_response(0, NULL, "gateway_shadow_storage_unavailable");
    }
    if (secret_supplied) {
        old_auth_key_present = gs_auth_key_snapshot(old_auth_key, sizeof(old_auth_key));
        if (old_auth_key_present < 0) {
            sqlite3_close(db); json_object_put(data);
            return gs_response(0, NULL, "auth_key_snapshot_failed");
        }
    }
    if (gs_exec(db, "BEGIN IMMEDIATE") != 0) {
        sqlite3_close(db); json_object_put(data);
        return gs_response(0, NULL, "gateway_shadow_transaction_failed");
    }
    transaction_started = 1;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_int(st, 1, gs_json_bool(cfg, "enabled", 0));
        sqlite3_bind_text(st, 2, gs_json_string(cfg, "role", "primary"), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 3, gs_json_string(cfg, "lan_interface", "br-lan"), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 4, gs_json_string(cfg, "management_ipv4", ""), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 5, gs_json_string(cfg, "heartbeat_interface", ""), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 6, gs_json_string(cfg, "heartbeat_local_ip", ""), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 7, gs_json_string(cfg, "heartbeat_peer_ip", ""), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 8, gs_json_int(cfg, "heartbeat_prefix_length", 30));
        sqlite3_bind_text(st, 9, gs_json_string(cfg, "virtual_ipv4", ""), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 10, gs_json_int(cfg, "virtual_router_id", 51));
        sqlite3_bind_int(st, 11, gs_json_int(cfg, "priority", 150));
        sqlite3_bind_int(st, 12, gs_json_int(cfg, "advert_interval_seconds", 1));
        sqlite3_bind_int(st, 13, gs_json_bool(cfg, "preempt", 0));
        sqlite3_bind_int(st, 14, gs_json_bool(cfg, "connection_sync", 1));
        sqlite3_bind_int64(st, 15, gs_now());
        rc = sqlite3_step(st) == SQLITE_DONE ? 0 : -1;
    }
    if (st) sqlite3_finalize(st);
    if (rc != 0) goto save_failed;
    if (secret_supplied && gs_auth_key_write_atomic(auth_key) != 0) {
        rc = -2; goto save_failed;
    }
    if (gs_exec(db, "COMMIT") != 0) { rc = -3; goto save_failed; }
    transaction_started = 0;
    sqlite3_close(db); db = NULL;
    json_object_object_add(data, "persisted", json_object_new_boolean(1));
    json_object_object_add(data, "applied", json_object_new_boolean(0));
    gs_add_string(data, "apply_state", "draft");
    (void)gs_auth_key_path(auth_key_path, sizeof(auth_key_path));
    json_object_object_add(data, "secret_configured",
                           json_object_new_boolean(secret_supplied ||
                                                   (auth_key_path[0] && access(auth_key_path, R_OK) == 0)));
    return gs_response(1, data, NULL);

save_failed:
    if (transaction_started) (void)gs_exec(db, "ROLLBACK");
    if (db) sqlite3_close(db);
    if (secret_supplied) gs_auth_key_restore(old_auth_key, old_auth_key_present);
    json_object_put(data);
    return gs_response(0, NULL, rc == -2 ? "auth_key_store_failed" :
                                  rc == -3 ? "gateway_shadow_commit_failed" :
                                             "gateway_shadow_save_failed");
}

/* Ensure the private runtime directory exists before rendering into it. */
static int gs_runtime_dir_ensure(void)
{
    const char *runtime_dir = gs_runtime_dir();
    struct stat status;
    if (!getenv("DREAMINGWRT_GATEWAY_SHADOW_DIR") &&
        mkdir("/etc/dreamingwrt", 0700) != 0 && errno != EEXIST)
        return -1;
    if (mkdir(runtime_dir, 0700) != 0 && errno != EEXIST) return -1;
    if (lstat(runtime_dir, &status) != 0 || !S_ISDIR(status.st_mode)) return -1;
    return chmod(runtime_dir, 0700) == 0 ? 0 : -1;
}

/* Persist the outcome of an apply attempt so status/ reflects reality. */
static void gs_runtime_record(const char *state, const char *last_error,
                              int managed_daemons, int touch_apply_time)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *st = NULL;
    if (gs_open(&db) != 0) return;
    if (sqlite3_prepare_v2(db,
            "UPDATE gateway_shadow_runtime SET state=?1,last_error=?2,"
            "managed_daemons=?3,last_transition_at=?4,"
            "last_apply_at=CASE WHEN ?5 THEN ?4 ELSE last_apply_at END,"
            "updated_at=?4 WHERE id=1", -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_text(st, 1, state ? state : "unknown", -1, SQLITE_STATIC);
        sqlite3_bind_text(st, 2, last_error ? last_error : "", -1, SQLITE_STATIC);
        sqlite3_bind_int(st, 3, managed_daemons ? 1 : 0);
        sqlite3_bind_int64(st, 4, gs_now());
        sqlite3_bind_int(st, 5, touch_apply_time ? 1 : 0);
        (void)sqlite3_step(st);
    }
    if (st) sqlite3_finalize(st);
    sqlite3_close(db);
}

static void gs_runtime_result_add(struct json_object *data, const char *key,
                                  const struct jmx_gateway_shadow_runtime_result *result)
{
    struct json_object *node = json_object_new_object();
    json_object_object_add(node, "code", json_object_new_int(result->code));
    if (result->system_errno)
        json_object_object_add(node, "errno", json_object_new_int(result->system_errno));
    if (result->child_exit_status)
        json_object_object_add(node, "child_exit_status",
                               json_object_new_int(result->child_exit_status));
    if (result->message[0]) gs_add_string(node, "message", result->message);
    if (result->child_output[0]) gs_add_string(node, "output", result->child_output);
    json_object_object_add(data, key, node);
}

/*
 * Apply is the only entry point that starts VRRP.  It refuses to act unless
 * preflight reports ready, which includes a mutually authenticated peer, a real
 * keepalived binary, and existing interfaces.  Rendering, config-testing, and
 * daemon control are delegated to jmx_gateway_shadow_runtime.c so that this
 * control plane never writes daemon files or execs binaries itself.
 */
struct json_object *jmx_gateway_shadow_apply(struct json_object *payload)
{
    sqlite3 *db = NULL;
    struct json_object *data = json_object_new_object();
    struct json_object *preflight = jmx_gateway_shadow_preflight(payload);
    struct json_object *preflight_data = NULL, *value = NULL, *cfg = NULL, *peer = NULL;
    struct jmx_gateway_shadow_runtime_config runtime;
    struct jmx_gateway_shadow_runtime_result result;
    char keepalived_bin[PATH_MAX], conntrackd_bin[PATH_MAX];
    const char *reason = NULL;
    int ready = 0, keepalived, conntrackd, paired, sync_wanted, enabled;
    int keepalived_was_running, managed = 0, rc;

    if (preflight && json_object_object_get_ex(preflight, "data", &preflight_data) &&
        preflight_data && json_object_object_get_ex(preflight_data, "ready", &value))
        ready = json_object_get_boolean(value);
    if (preflight_data && json_object_object_get_ex(preflight_data, "reason", &value) &&
        value && json_object_is_type(value, json_type_string))
        reason = json_object_get_string(value);

    keepalived = gs_binary_path("keepalived", keepalived_bin, sizeof(keepalived_bin));
    conntrackd = gs_binary_path("conntrackd", conntrackd_bin, sizeof(conntrackd_bin));

    if (jmx_gateway_shadow_schema_ensure() != 0 || gs_open(&db) != 0) {
        if (preflight) json_object_put(preflight);
        json_object_put(data);
        return gs_response(0, NULL, "gateway_shadow_storage_unavailable");
    }
    cfg = gs_config_read(db);
    peer = gs_peer_read(db);
    sqlite3_close(db);
    if (!cfg || !peer) {
        if (cfg) json_object_put(cfg);
        if (peer) json_object_put(peer);
        if (preflight) json_object_put(preflight);
        json_object_put(data);
        return gs_response(0, NULL, "gateway_shadow_read_failed");
    }
    paired = gs_peer_paired(peer);
    enabled = gs_json_bool(cfg, "enabled", 0);
    sync_wanted = gs_json_bool(cfg, "connection_sync", 1);

    json_object_object_add(data, "preflight_ready", json_object_new_boolean(ready));
    if (preflight_data)
        json_object_object_add(data, "preflight", json_object_get(preflight_data));
    json_object_object_add(data, "capabilities",
                           gs_capabilities(keepalived, conntrackd, paired));

    /* Refuse before touching the filesystem when preflight is not ready. */
    if (!ready || !enabled) {
        const char *blocked = !enabled ? "gateway_shadow_disabled" :
                              reason && reason[0] ? reason : "preflight_failed";
        gs_runtime_record("blocked", blocked, 0, 0);
        json_object_object_add(data, "persisted", json_object_new_boolean(0));
        json_object_object_add(data, "applied", json_object_new_boolean(0));
        json_object_object_add(data, "changed", json_object_new_boolean(0));
        json_object_object_add(data, "rollback_available", json_object_new_boolean(0));
        gs_add_string(data, "state", "blocked");
        gs_add_string(data, "reason", blocked);
        json_object_put(cfg); json_object_put(peer);
        if (preflight) json_object_put(preflight);
        return gs_response(0, data, !enabled ? "gateway_shadow_disabled" :
                                     "gateway_shadow_preflight_not_ready");
    }

    if (gs_runtime_dir_ensure() != 0) {
        gs_runtime_record("blocked", "runtime_directory_unavailable", 0, 0);
        json_object_object_add(data, "persisted", json_object_new_boolean(0));
        json_object_object_add(data, "applied", json_object_new_boolean(0));
        json_object_object_add(data, "changed", json_object_new_boolean(0));
        gs_add_string(data, "state", "blocked");
        gs_add_string(data, "reason", "runtime_directory_unavailable");
        json_object_put(cfg); json_object_put(peer);
        if (preflight) json_object_put(preflight);
        return gs_response(0, data, "gateway_shadow_runtime_directory_failed");
    }

    memset(&runtime, 0, sizeof(runtime));
    runtime.role = gs_json_string(cfg, "role", "primary");
    runtime.lan_interface = gs_json_string(cfg, "lan_interface", "");
    runtime.heartbeat_interface = gs_json_string(cfg, "heartbeat_interface", "");
    runtime.heartbeat_local_ip = gs_json_string(cfg, "heartbeat_local_ip", "");
    runtime.heartbeat_peer_ip = gs_json_string(cfg, "heartbeat_peer_ip", "");
    runtime.virtual_ipv4 = gs_json_string(cfg, "virtual_ipv4", "");
    runtime.virtual_router_id = (unsigned int)gs_json_int(cfg, "virtual_router_id", 51);
    runtime.priority = (unsigned int)gs_json_int(cfg, "priority", 150);
    runtime.advert_interval_seconds =
        (unsigned int)gs_json_int(cfg, "advert_interval_seconds", 1);
    runtime.preempt = gs_json_bool(cfg, "preempt", 0);
    runtime.connection_sync = sync_wanted && conntrackd ? 1 : 0;

    rc = jmx_gateway_shadow_runtime_render(&runtime, gs_runtime_dir(), &result);
    gs_runtime_result_add(data, "render", &result);
    if (rc != JMX_GS_RUNTIME_OK) {
        gs_runtime_record("blocked", "runtime_render_failed", 0, 0);
        json_object_object_add(data, "persisted", json_object_new_boolean(0));
        json_object_object_add(data, "applied", json_object_new_boolean(0));
        json_object_object_add(data, "changed", json_object_new_boolean(0));
        gs_add_string(data, "state", "blocked");
        gs_add_string(data, "reason", "runtime_render_failed");
        json_object_put(cfg); json_object_put(peer);
        if (preflight) json_object_put(preflight);
        return gs_response(0, data, "gateway_shadow_render_failed");
    }
    json_object_object_add(data, "persisted", json_object_new_boolean(1));
    gs_add_string(data, "keepalived_config", result.keepalived_path);
    gs_add_string(data, "conntrackd_config", result.conntrackd_path);

    {
        char keepalived_cfg[PATH_MAX], conntrackd_cfg[PATH_MAX];
        snprintf(keepalived_cfg, sizeof(keepalived_cfg), "%s", result.keepalived_path);
        snprintf(conntrackd_cfg, sizeof(conntrackd_cfg), "%s", result.conntrackd_path);

        rc = jmx_gateway_shadow_runtime_config_test(JMX_GS_DAEMON_KEEPALIVED,
                                                   keepalived_bin, keepalived_cfg,
                                                   &result);
        gs_runtime_result_add(data, "config_test", &result);
        if (rc != JMX_GS_RUNTIME_OK) {
            gs_runtime_record("blocked", "keepalived_config_test_failed", 0, 0);
            json_object_object_add(data, "applied", json_object_new_boolean(0));
            json_object_object_add(data, "changed", json_object_new_boolean(0));
            gs_add_string(data, "state", "blocked");
            gs_add_string(data, "reason", "keepalived_config_test_failed");
            json_object_put(cfg); json_object_put(peer);
            if (preflight) json_object_put(preflight);
            return gs_response(0, data, "gateway_shadow_config_test_failed");
        }

        /*
         * A live Shadow keepalived is reloaded in place so an established
         * VRRP session is not dropped; otherwise it is started.
         */
        keepalived_was_running = gs_pid_alive(GS_KEEPALIVED_PID);
        rc = jmx_gateway_shadow_runtime_daemon_control(
            JMX_GS_DAEMON_KEEPALIVED,
            keepalived_was_running ? JMX_GS_DAEMON_RELOAD : JMX_GS_DAEMON_START,
            keepalived_bin, keepalived_cfg, &result);
        gs_runtime_result_add(data, "keepalived", &result);
        if (rc != JMX_GS_RUNTIME_OK) {
            gs_runtime_record("blocked", "keepalived_control_failed",
                              keepalived_was_running, 1);
            json_object_object_add(data, "applied", json_object_new_boolean(0));
            json_object_object_add(data, "changed", json_object_new_boolean(0));
            gs_add_string(data, "state", "blocked");
            gs_add_string(data, "reason", "keepalived_control_failed");
            json_object_put(cfg); json_object_put(peer);
            if (preflight) json_object_put(preflight);
            return gs_response(0, data, "gateway_shadow_keepalived_failed");
        }
        managed = 1;

        /*
         * conntrackd has no atomic reload, so a controlled stop/start is the
         * only correct sequence.  A sync failure degrades session continuity
         * but must not tear down an already-running VRRP instance.
         */
        if (runtime.connection_sync) {
            (void)jmx_gateway_shadow_runtime_daemon_control(
                JMX_GS_DAEMON_CONNTRACKD, JMX_GS_DAEMON_STOP,
                conntrackd_bin, conntrackd_cfg, &result);
            rc = jmx_gateway_shadow_runtime_daemon_control(
                JMX_GS_DAEMON_CONNTRACKD, JMX_GS_DAEMON_START,
                conntrackd_bin, conntrackd_cfg, &result);
            gs_runtime_result_add(data, "conntrackd", &result);
            json_object_object_add(data, "connection_sync_active",
                                   json_object_new_boolean(rc == JMX_GS_RUNTIME_OK));
            if (rc != JMX_GS_RUNTIME_OK)
                gs_add_string(data, "connection_sync_error", "conntrackd_control_failed");
        } else {
            json_object_object_add(data, "connection_sync_active",
                                   json_object_new_boolean(0));
            if (sync_wanted && !conntrackd)
                gs_add_string(data, "connection_sync_error", "conntrackd_not_installed");
        }
    }

    gs_runtime_record("active", "", managed, 1);
    json_object_object_add(data, "applied", json_object_new_boolean(1));
    json_object_object_add(data, "changed", json_object_new_boolean(1));
    json_object_object_add(data, "rollback_available", json_object_new_boolean(1));
    json_object_object_add(data, "managed_daemons", json_object_new_boolean(managed));
    gs_add_string(data, "state", "active");
    gs_add_string(data, "apply_state", "applied");
    json_object_put(cfg); json_object_put(peer);
    if (preflight) json_object_put(preflight);
    return gs_response(1, data, NULL);
}

struct json_object *jmx_gateway_shadow_disable(struct json_object *payload)
{
    sqlite3 *db = NULL;
    struct json_object *data = json_object_new_object();
    (void)payload;
    if (jmx_gateway_shadow_schema_ensure() != 0 || gs_open(&db) != 0) {
        json_object_put(data); return gs_response(0, NULL, "gateway_shadow_storage_unavailable");
    }
    if (gs_exec(db, "BEGIN IMMEDIATE;"
                    "UPDATE gateway_shadow_config SET enabled=0,revision=revision+1,updated_at=strftime('%s','now') WHERE id=1;"
                    "UPDATE gateway_shadow_runtime SET state='inactive',vrrp_state='unknown',"
                    "last_error='',managed_daemons=0,updated_at=strftime('%s','now') WHERE id=1;"
                    "COMMIT;") != 0) {
        (void)gs_exec(db, "ROLLBACK"); sqlite3_close(db); json_object_put(data);
        return gs_response(0, NULL, "gateway_shadow_disable_failed");
    }
    sqlite3_close(db);
    /*
     * Disabling must also stop the daemons this control plane started,
     * otherwise a stale keepalived would keep announcing the virtual address
     * after the operator turned the feature off.
     */
    {
        struct jmx_gateway_shadow_runtime_result result;
        char binary[PATH_MAX], config_path[PATH_MAX];
        int stopped_keepalived = 0, stopped_conntrackd = 0;
        snprintf(config_path, sizeof(config_path), "%s/keepalived.conf",
                 gs_runtime_dir());
        if (gs_pid_alive(GS_KEEPALIVED_PID) &&
            gs_binary_path("keepalived", binary, sizeof(binary)) &&
            jmx_gateway_shadow_runtime_daemon_control(
                JMX_GS_DAEMON_KEEPALIVED, JMX_GS_DAEMON_STOP, binary,
                config_path, &result) == JMX_GS_RUNTIME_OK)
            stopped_keepalived = 1;
        snprintf(config_path, sizeof(config_path), "%s/conntrackd.conf",
                 gs_runtime_dir());
        if (gs_conntrackd_running() &&
            gs_binary_path("conntrackd", binary, sizeof(binary)) &&
            jmx_gateway_shadow_runtime_daemon_control(
                JMX_GS_DAEMON_CONNTRACKD, JMX_GS_DAEMON_STOP, binary,
                config_path, &result) == JMX_GS_RUNTIME_OK)
            stopped_conntrackd = 1;
        json_object_object_add(data, "keepalived_stopped",
                               json_object_new_boolean(stopped_keepalived));
        json_object_object_add(data, "conntrackd_stopped",
                               json_object_new_boolean(stopped_conntrackd));
    }
    json_object_object_add(data, "persisted", json_object_new_boolean(1));
    json_object_object_add(data, "applied", json_object_new_boolean(1));
    json_object_object_add(data, "changed", json_object_new_boolean(1));
    gs_add_string(data, "state", "inactive");
    return gs_response(1, data, NULL);
}

static struct json_object *gs_pairing_disabled(void)
{
    struct json_object *data = json_object_new_object();
    json_object_object_add(data, "pairing_supported", json_object_new_boolean(0));
    json_object_object_add(data, "paired", json_object_new_boolean(0));
    json_object_object_add(data, "changed", json_object_new_boolean(0));
    gs_add_string(data, "reason", "mutual_authenticated_peer_pairing_pending");
    return gs_response(0, data, "capability_disabled");
}

/*
 * Authenticated peer pairing is implemented in jmx_gateway_shadow_pairing.c
 * (Ed25519 offer/accept/confirm over config.db).  These entry points used to
 * be hard stubs returning capability_disabled because that translation unit
 * was never listed in the Makefile, so the implementation was compiled out
 * entirely.  Now that it is linked in, forward to the real protocol and only
 * fall back to the disabled response when the pairing schema cannot be
 * initialised - that is a genuine storage fault, not a missing capability.
 */
struct json_object *jmx_gateway_shadow_pairing_start(struct json_object *payload)
{
    if (jmx_gateway_shadow_pairing_schema_ensure() != 0)
        return gs_pairing_disabled();
    return jmx_gateway_shadow_pairing_protocol_start(payload);
}

struct json_object *jmx_gateway_shadow_pairing_approve(struct json_object *payload)
{
    if (jmx_gateway_shadow_pairing_schema_ensure() != 0)
        return gs_pairing_disabled();
    return jmx_gateway_shadow_pairing_protocol_approve(payload);
}
