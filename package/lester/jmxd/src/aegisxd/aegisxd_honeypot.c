// SPDX-License-Identifier: GPL-2.0-or-later
#include "aegisxd_internal.h"
#include "jmx_strbuf.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <sys/wait.h>

#define HONEYPOT_TABLE "dreamingwrt_honeypot"
#define HONEYPOT_DEVICE "dwrt-hpot0"
#define HONEYPOT_LOG "/tmp/dreamingwrt-honeypot-apply.log"
#define HONEYPOT_MAX_CONFIGS 16
#define HONEYPOT_MAX_SERVICES 8
#define HONEYPOT_MAX_ADDRESSES_PER_NETWORK 4
#define HONEYPOT_EVENT_DEDUPE_S 10
#define AEGISXD_HONEYPOT_MAX_EVENT_BYTES 8192

struct honeypot_service {
    const char *name;
    const char *transport;
    int external_port;
    int listen_port;
};

static const struct honeypot_service g_honeypot_services[] = {
    { "ftp", "tcp", 21, 22021 },
    { "ssh", "tcp", 22, 22022 },
    { "telnet", "tcp", 23, 22023 },
    { "dns", "udp", 53, 22053 },
    { "http", "tcp", 80, 22080 },
};

static char g_honeypot_ingest_token[65];
static int honeypot_process_running(void);

static int honeypot_generate_ingest_token(void)
{
    unsigned char raw[32];
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    size_t offset = 0;

    if (fd < 0)
        return -1;
    while (offset < sizeof(raw)) {
        ssize_t n = read(fd, raw + offset, sizeof(raw) - offset);

        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0) {
            close(fd);
            return -1;
        }
        offset += (size_t)n;
    }
    close(fd);
    for (offset = 0; offset < sizeof(raw); offset++)
        snprintf(g_honeypot_ingest_token + offset * 2,
                 sizeof(g_honeypot_ingest_token) - offset * 2, "%02x", raw[offset]);
    return 0;
}

static int honeypot_exec(char *const argv[])
{
    pid_t pid;
    int status = 0;
    struct sigaction old_chld, dfl_chld;
    int have_old = 0;

    if (!argv || !argv[0] || argv[0][0] != '/')
        return -1;
    memset(&dfl_chld, 0, sizeof(dfl_chld));
    dfl_chld.sa_handler = SIG_DFL;
    sigemptyset(&dfl_chld.sa_mask);
    if (sigaction(SIGCHLD, &dfl_chld, &old_chld) == 0)
        have_old = 1;
    pid = fork();
    if (pid < 0)
        goto failed;
    if (pid == 0) {
        int fd = open(HONEYPOT_LOG, O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (fd >= 0) {
            dup2(fd, STDOUT_FILENO);
            dup2(fd, STDERR_FILENO);
            close(fd);
        }
        setenv("PATH", "/usr/sbin:/usr/bin:/sbin:/bin", 1);
        execv(argv[0], argv);
        _exit(127);
    }
    while (waitpid(pid, &status, 0) < 0) {
        if (errno == EINTR)
            continue;
        goto failed;
    }
    if (have_old)
        sigaction(SIGCHLD, &old_chld, NULL);
    if (WIFEXITED(status))
        return WEXITSTATUS(status);
    if (WIFSIGNALED(status))
        return 128 + WTERMSIG(status);
    return -1;
failed:
    if (have_old)
        sigaction(SIGCHLD, &old_chld, NULL);
    return -1;
}

static int honeypot_run(const char *a0, const char *a1, const char *a2,
                        const char *a3, const char *a4, const char *a5)
{
    char *argv[7];
    const char *args[] = { a0, a1, a2, a3, a4, a5 };
    size_t i, n = 0;

    for (i = 0; i < ARRAY_SIZE(args) && args[i]; i++)
        argv[n++] = (char *)args[i];
    argv[n] = NULL;
    return honeypot_exec(argv);
}

static int honeypot_text_ok(const char *s, size_t max, int required)
{
    size_t i, len;
    if (!s || !(len = strlen(s)))
        return !required;
    if (len > max)
        return 0;
    for (i = 0; i < len; i++)
        if ((unsigned char)s[i] < 0x20 || (unsigned char)s[i] == 0x7f)
            return 0;
    return 1;
}

static int honeypot_id_ok(const char *id)
{
    size_t i, n;
    if (!id || !(n = strlen(id)) || n > 64)
        return 0;
    for (i = 0; i < n; i++)
        if (!(isalnum((unsigned char)id[i]) || id[i] == '-' || id[i] == '_'))
            return 0;
    return 1;
}

static int honeypot_iface_ok(const char *name)
{
    size_t i, n;
    if (!name || !(n = strlen(name)) || n >= IFNAMSIZ)
        return 0;
    for (i = 0; i < n; i++)
        if (!(isalnum((unsigned char)name[i]) || name[i] == '-' ||
              name[i] == '_' || name[i] == '.'))
            return 0;
    return 1;
}

static const struct honeypot_service *honeypot_service_find(const char *name)
{
    size_t i;
    for (i = 0; i < ARRAY_SIZE(g_honeypot_services); i++)
        if (name && !strcmp(name, g_honeypot_services[i].name))
            return &g_honeypot_services[i];
    return NULL;
}

static int honeypot_profile_ok(const char *profile)
{
    return profile && (!strcmp(profile, "linux_server") || !strcmp(profile, "nas") ||
                       !strcmp(profile, "iot_camera") || !strcmp(profile, "windows_host") ||
                       !strcmp(profile, "custom"));
}

static struct json_object *honeypot_profile_services(const char *profile)
{
    struct json_object *services = json_object_new_array();
    const char *names[5];
    size_t count = 0, i;

    if (!strcmp(profile, "nas")) {
        names[count++] = "http"; names[count++] = "ftp";
    } else if (!strcmp(profile, "iot_camera")) {
        names[count++] = "telnet"; names[count++] = "http";
    } else if (!strcmp(profile, "windows_host")) {
        /* SMB/RDP remain explicitly unsupported in phase one. */
        names[count++] = "http";
    } else {
        names[count++] = "ssh"; names[count++] = "http"; names[count++] = "ftp";
        names[count++] = "dns";
    }
    for (i = 0; i < count; i++)
        json_object_array_add(services, json_object_new_string(names[i]));
    return services;
}

static struct json_object *honeypot_normalize_services(struct json_object *body,
                                                       const char *profile,
                                                       const char **error)
{
    struct json_object *input = NULL;
    struct json_object *out = json_object_new_array();
    int count, i;

    if (!json_object_object_get_ex(body, "services", &input) || !input)
        input = honeypot_profile_services(profile);
    else
        json_object_get(input);
    if (!json_object_is_type(input, json_type_array) ||
        (count = (int)json_object_array_length(input)) < 1 || count > HONEYPOT_MAX_SERVICES) {
        *error = "invalid_services";
        goto failed;
    }
    for (i = 0; i < count; i++) {
        struct json_object *entry = json_object_array_get_idx(input, i);
        const char *name;
        const struct honeypot_service *service;
        int j;

        if (!entry || !json_object_is_type(entry, json_type_string)) {
            *error = "invalid_services";
            goto failed;
        }
        name = json_object_get_string(entry);
        service = honeypot_service_find(name);
        if (!service) {
            *error = "unsupported_honeypot_service";
            goto failed;
        }
        for (j = 0; j < (int)json_object_array_length(out); j++)
            if (!strcmp(name, json_object_get_string(json_object_array_get_idx(out, j)))) {
                *error = "duplicate_honeypot_service";
                goto failed;
            }
        json_object_array_add(out, json_object_new_string(name));
    }
    json_object_put(input);
    return out;
failed:
    json_object_put(input);
    json_object_put(out);
    return NULL;
}

static int honeypot_ipv4_parse(const char *text, uint32_t *host)
{
    struct in_addr addr;
    if (!text || inet_pton(AF_INET, text, &addr) != 1)
        return 0;
    if (host)
        *host = ntohl(addr.s_addr);
    return 1;
}

static uint32_t honeypot_mask(int prefix)
{
    return prefix <= 0 ? 0 : prefix >= 32 ? UINT32_MAX : UINT32_MAX << (32 - prefix);
}

static int honeypot_address_in_use_runtime(const char *address)
{
    struct ifaddrs *all = NULL, *it;
    FILE *fp;
    char line[512], ip[64];
    int used = 0;

    if (getifaddrs(&all) == 0) {
        for (it = all; it; it = it->ifa_next) {
            char buf[INET_ADDRSTRLEN];
            struct sockaddr_in *sin;
            if (!it->ifa_addr || it->ifa_addr->sa_family != AF_INET)
                continue;
            sin = (struct sockaddr_in *)it->ifa_addr;
            if (inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf)) && !strcmp(buf, address)) {
                used = 1;
                break;
            }
        }
        freeifaddrs(all);
    }
    if (used)
        return 1;
    fp = fopen("/proc/net/arp", "r");
    if (fp) {
        while (fgets(line, sizeof(line), fp)) {
            if (sscanf(line, "%63s", ip) == 1 && !strcmp(ip, address)) {
                used = 1;
                break;
            }
        }
        fclose(fp);
    }
    if (used)
        return 1;
    fp = fopen("/tmp/dhcp.leases", "r");
    if (!fp)
        fp = fopen("/var/dhcp.leases", "r");
    if (fp) {
        char expiry[32], mac[32], host[256], client[256];
        while (fgets(line, sizeof(line), fp)) {
            if (sscanf(line, "%31s %31s %63s %255s %255s", expiry, mac, ip, host, client) >= 3 &&
                !strcmp(ip, address)) {
                used = 1;
                break;
            }
        }
        fclose(fp);
    }
    return used;
}

static int honeypot_config_address_exists(const char *address, const char *exclude_id)
{
    sqlite3_stmt *st = aegisxd_config_prepare(
        "SELECT 1 FROM aegis_honeypots WHERE address=?1 AND id<>?2 LIMIT 1");
    int exists = 0;
    if (!st)
        return 1;
    sqlite3_bind_text(st, 1, address, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, exclude_id ? exclude_id : "", -1, SQLITE_TRANSIENT);
    exists = sqlite3_step(st) == SQLITE_ROW;
    sqlite3_finalize(st);
    return exists;
}

static int honeypot_network_address_count(const char *network_id, const char *exclude_id)
{
    sqlite3_stmt *st = aegisxd_config_prepare(
        "SELECT COUNT(*) FROM aegis_honeypots WHERE network_id=?1 AND id<>?2");
    int count = HONEYPOT_MAX_ADDRESSES_PER_NETWORK;

    if (!st)
        return count;
    sqlite3_bind_text(st, 1, network_id ? network_id : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, exclude_id ? exclude_id : "", -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW)
        count = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    return count;
}

static int honeypot_config_owns_runtime_address(const char *address, const char *id)
{
    sqlite3_stmt *st;
    int owns = 0;

    if (!id || !id[0])
        return 0;
    st = aegisxd_config_prepare(
        "SELECT 1 FROM aegis_honeypots WHERE id=?1 AND address=?2 AND enabled=1 LIMIT 1");
    if (!st)
        return 0;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, address, -1, SQLITE_TRANSIENT);
    owns = sqlite3_step(st) == SQLITE_ROW;
    sqlite3_finalize(st);
    return owns;
}

static int honeypot_network_load(const char *network_id, char *iface, size_t iface_len,
                                  char *gateway, size_t gateway_len, int *prefix,
                                  char *pool_start, size_t pool_start_len,
                                  char *pool_end, size_t pool_end_len)
{
    sqlite3_stmt *st = aegisxd_config_prepare(
        "SELECT COALESCE(NULLIF(l.device,''),l.ifname),a.ip,a.prefix,"
        "COALESCE(d.pool_start,''),COALESCE(d.pool_end,'') "
        "FROM lan l JOIN lan_address a ON a.lan_id=l.id AND a.is_primary=1 "
        "LEFT JOIN lan_dhcp d ON d.lan_id=l.id WHERE l.id=?1 AND l.enabled=1 LIMIT 1");
    int ok = 0;
    if (!st)
        return -1;
    sqlite3_bind_text(st, 1, network_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW) {
        snprintf(iface, iface_len, "%s", aegisxd_sqlite_text(st, 0, ""));
        snprintf(gateway, gateway_len, "%s", aegisxd_sqlite_text(st, 1, ""));
        *prefix = sqlite3_column_int(st, 2);
        snprintf(pool_start, pool_start_len, "%s", aegisxd_sqlite_text(st, 3, ""));
        snprintf(pool_end, pool_end_len, "%s", aegisxd_sqlite_text(st, 4, ""));
        ok = iface[0] && gateway[0] && honeypot_iface_ok(iface) && *prefix >= 8 && *prefix <= 30;
    }
    sqlite3_finalize(st);
    return ok ? 0 : -1;
}

static int honeypot_db_reserved(const char *address)
{
    sqlite3_stmt *st = aegisxd_config_prepare(
        "SELECT 1 FROM dhcp_reservation WHERE ip=?1 AND enabled=1 "
        "UNION SELECT 1 FROM dhcp_lease_cache WHERE ip=?1 AND online=1 LIMIT 1");
    int found = 0;
    if (!st)
        return 0;
    sqlite3_bind_text(st, 1, address, -1, SQLITE_TRANSIENT);
    found = sqlite3_step(st) == SQLITE_ROW;
    sqlite3_finalize(st);
    return found;
}

static int honeypot_validate_address(const char *address, const char *gateway, int prefix,
                                      const char *pool_start, const char *pool_end,
                                      const char *exclude_id, const char **reason)
{
    uint32_t ip, gw, mask, network, broadcast, start = 0, end = 0;
    char *tail = NULL;
    long host;
    if (!honeypot_ipv4_parse(address, &ip) || !honeypot_ipv4_parse(gateway, &gw)) {
        *reason = "invalid_ipv4_address";
        return -1;
    }
    mask = honeypot_mask(prefix);
    network = gw & mask;
    broadcast = network | ~mask;
    if ((ip & mask) != network) { *reason = "address_outside_network"; return -1; }
    if (ip == network || ip == broadcast || ip == gw) {
        *reason = "address_reserved_by_network"; return -1;
    }
    if (pool_start[0] && !honeypot_ipv4_parse(pool_start, &start)) {
        host = strtol(pool_start, &tail, 10);
        if (tail && !*tail && host > 0 && host < 256)
            start = network | (uint32_t)host;
    }
    tail = NULL;
    if (pool_end[0] && !honeypot_ipv4_parse(pool_end, &end)) {
        host = strtol(pool_end, &tail, 10);
        if (tail && !*tail && host > 0 && host < 256)
            end = network | (uint32_t)host;
    }
    if (start && end && start <= end && ip >= start && ip <= end) {
        *reason = "address_inside_dhcp_pool"; return -1;
    }
    if (honeypot_db_reserved(address)) { *reason = "address_reserved_or_leased"; return -1; }
    if (honeypot_config_address_exists(address, exclude_id)) {
        *reason = "honeypot_address_conflict"; return -1;
    }
    if (!honeypot_config_owns_runtime_address(address, exclude_id) &&
        honeypot_address_in_use_runtime(address)) {
        *reason = "address_in_use"; return -1;
    }
    return 0;
}

static struct json_object *honeypot_service_runtime(const char *name)
{
    const struct honeypot_service *service = honeypot_service_find(name);
    struct json_object *out;
    if (!service)
        return NULL;
    out = json_object_new_object();
    aegisxd_json_add_string(out, "name", service->name);
    aegisxd_json_add_string(out, "transport", service->transport);
    json_object_object_add(out, "external_port", json_object_new_int(service->external_port));
    json_object_object_add(out, "listen_port", json_object_new_int(service->listen_port));
    return out;
}

static struct json_object *honeypot_config_array(int enabled_only)
{
    struct json_object *arr = json_object_new_array();
    sqlite3_stmt *st = aegisxd_config_prepare(
        enabled_only ?
        "SELECT id,name,enabled,network_id,interface,address,profile,services_json,max_connections,"
        "max_per_source,capture_bytes,idle_timeout,session_timeout,apply_state,last_error,created_at,updated_at "
        "FROM aegis_honeypots WHERE enabled=1 ORDER BY network_id,address" :
        "SELECT id,name,enabled,network_id,interface,address,profile,services_json,max_connections,"
        "max_per_source,capture_bytes,idle_timeout,session_timeout,apply_state,last_error,created_at,updated_at "
        "FROM aegis_honeypots ORDER BY network_id,address");
    while (st && sqlite3_step(st) == SQLITE_ROW) {
        struct json_object *item = json_object_new_object();
        struct json_object *raw = json_tokener_parse(aegisxd_sqlite_text(st, 7, "[]"));
        struct json_object *services = json_object_new_array();
        int i;
        aegisxd_json_add_string(item, "id", aegisxd_sqlite_text(st, 0, ""));
        aegisxd_json_add_string(item, "name", aegisxd_sqlite_text(st, 1, ""));
        json_object_object_add(item, "enabled", json_object_new_boolean(sqlite3_column_int(st, 2)));
        aegisxd_json_add_string(item, "network_id", aegisxd_sqlite_text(st, 3, ""));
        aegisxd_json_add_string(item, "interface", aegisxd_sqlite_text(st, 4, ""));
        aegisxd_json_add_string(item, "address", aegisxd_sqlite_text(st, 5, ""));
        aegisxd_json_add_string(item, "profile", aegisxd_sqlite_text(st, 6, ""));
        if (raw && json_object_is_type(raw, json_type_array))
            for (i = 0; i < (int)json_object_array_length(raw); i++) {
                struct json_object *entry = json_object_array_get_idx(raw, i);
                struct json_object *service = honeypot_service_runtime(
                    entry && json_object_is_type(entry, json_type_string) ? json_object_get_string(entry) : "");
                if (service)
                    json_object_array_add(services, service);
            }
        if (raw) json_object_put(raw);
        json_object_object_add(item, "services", services);
        json_object_object_add(item, "max_connections", json_object_new_int(sqlite3_column_int(st, 8)));
        json_object_object_add(item, "max_per_source", json_object_new_int(sqlite3_column_int(st, 9)));
        json_object_object_add(item, "capture_bytes", json_object_new_int(sqlite3_column_int(st, 10)));
        json_object_object_add(item, "idle_timeout", json_object_new_int(sqlite3_column_int(st, 11)));
        json_object_object_add(item, "session_timeout", json_object_new_int(sqlite3_column_int(st, 12)));
        aegisxd_json_add_string(item, "apply_state",
                                enabled_only ? "active" : aegisxd_sqlite_text(st, 13, ""));
        aegisxd_json_add_string(item, "last_error", aegisxd_sqlite_text(st, 14, ""));
        json_object_object_add(item, "created_at", json_object_new_int64(sqlite3_column_int64(st, 15)));
        json_object_object_add(item, "updated_at", json_object_new_int64(sqlite3_column_int64(st, 16)));
        json_object_array_add(arr, item);
    }
    if (st) sqlite3_finalize(st);
    return arr;
}

static int honeypot_write_atomic(const char *path, const char *text, mode_t mode)
{
    char tmp[AEGISXD_MAX_PATH + 16];
    int fd, dirfd, rc = -1;
    size_t len = strlen(text), off = 0;
    ssize_t n;
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);
    if (fd < 0)
        return -1;
    while (off < len) {
        n = write(fd, text + off, len - off);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) goto out;
        off += (size_t)n;
    }
    if (fsync(fd) != 0 || close(fd) != 0) { fd = -1; goto out; }
    fd = -1;
    if (rename(tmp, path) != 0) goto out;
    dirfd = open(AEGISXD_RUNTIME_DIR, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dirfd >= 0) { (void)fsync(dirfd); close(dirfd); }
    rc = 0;
out:
    if (fd >= 0) close(fd);
    if (rc != 0) unlink(tmp);
    return rc;
}

static int honeypot_write_runtime(struct json_object *configs)
{
    struct json_object *root = json_object_new_object();
    struct json_object *limits = json_object_new_object();
    const char *text;
    int rc;
    if (json_object_array_length(configs) > 0 && honeypot_generate_ingest_token() != 0) {
        json_object_put(root);
        json_object_put(limits);
        return -1;
    }
    if (json_object_array_length(configs) == 0)
        g_honeypot_ingest_token[0] = '\0';
    json_object_object_add(root, "schema_version", json_object_new_int(1));
    json_object_object_add(root, "enabled", json_object_new_boolean(json_object_array_length(configs) > 0));
    json_object_object_add(root, "ingest_token",
                           json_object_new_string(g_honeypot_ingest_token));
    json_object_object_add(root, "generation", json_object_new_int64(aegisxd_now_s()));
    json_object_object_add(limits, "max_connections", json_object_new_int(128));
    json_object_object_add(limits, "max_per_source", json_object_new_int(8));
    json_object_object_add(limits, "capture_bytes", json_object_new_int(4096));
    json_object_object_add(limits, "idle_timeout", json_object_new_int(20));
    json_object_object_add(limits, "session_timeout", json_object_new_int(60));
    json_object_object_add(root, "limits", limits);
    json_object_object_add(root, "honeypots", json_object_get(configs));
    text = json_object_to_json_string_ext(root, JSON_C_TO_STRING_PRETTY);
    rc = honeypot_write_atomic(AEGISXD_HONEYPOT_RUNTIME_PATH, text, 0640);
    json_object_put(root);
    return rc;
}

static int honeypot_write_nft(struct json_object *configs, const char *path,
                              int replace_existing)
{
    FILE *fp = fopen(path, "w");
    int i, j;
    if (!fp)
        return -1;
    if (replace_existing)
        fprintf(fp, "delete table inet %s\n", HONEYPOT_TABLE);
    fprintf(fp, "table inet %s {\n", HONEYPOT_TABLE);
    fprintf(fp, " chain prefilter { type filter hook prerouting priority -110; policy accept;\n");
    for (i = 0; i < (int)json_object_array_length(configs); i++) {
        struct json_object *item = json_object_array_get_idx(configs, i);
        struct json_object *services = NULL;
        const char *address = aegisxd_json_str(item, "address", "");
        const char *iface = aegisxd_json_str(item, "interface", "");
        int tcp_count = 0, udp_count = 0;
        fprintf(fp, "  ip daddr %s iifname != \"%s\" drop\n", address, iface);
        json_object_object_get_ex(item, "services", &services);
        for (j = 0; services && j < (int)json_object_array_length(services); j++) {
            struct json_object *service = json_object_array_get_idx(services, j);
            if (!strcmp(aegisxd_json_str(service, "transport", ""), "tcp"))
                tcp_count++;
            else if (!strcmp(aegisxd_json_str(service, "transport", ""), "udp"))
                udp_count++;
        }
        if (tcp_count) {
            int emitted = 0;
            fprintf(fp, "  ip daddr %s tcp dport != { ", address);
            for (j = 0; services && j < (int)json_object_array_length(services); j++) {
                struct json_object *service = json_object_array_get_idx(services, j);
                if (!strcmp(aegisxd_json_str(service, "transport", ""), "tcp"))
                    fprintf(fp, "%s%d", emitted++ ? ", " : "",
                            json_object_get_int(json_object_object_get(service, "external_port")));
            }
            fprintf(fp, " } drop\n");
        } else {
            fprintf(fp, "  ip daddr %s meta l4proto tcp drop\n", address);
        }
        if (udp_count) {
            int emitted = 0;
            fprintf(fp, "  ip daddr %s udp dport != { ", address);
            for (j = 0; services && j < (int)json_object_array_length(services); j++) {
                struct json_object *service = json_object_array_get_idx(services, j);
                if (!strcmp(aegisxd_json_str(service, "transport", ""), "udp"))
                    fprintf(fp, "%s%d", emitted++ ? ", " : "",
                            json_object_get_int(json_object_object_get(service, "external_port")));
            }
            fprintf(fp, " } drop\n");
        } else {
            fprintf(fp, "  ip daddr %s meta l4proto udp drop\n", address);
        }
    }
    fprintf(fp, " }\n chain prerouting_redirect { type nat hook prerouting priority dstnat; policy accept;\n");
    for (i = 0; i < (int)json_object_array_length(configs); i++) {
        struct json_object *item = json_object_array_get_idx(configs, i);
        struct json_object *services = NULL;
        const char *address = aegisxd_json_str(item, "address", "");
        const char *iface = aegisxd_json_str(item, "interface", "");
        json_object_object_get_ex(item, "services", &services);
        for (j = 0; services && j < (int)json_object_array_length(services); j++) {
            struct json_object *service = json_object_array_get_idx(services, j);
            const char *transport = aegisxd_json_str(service, "transport", "");
            int external = json_object_get_int(json_object_object_get(service, "external_port"));
            int listen = json_object_get_int(json_object_object_get(service, "listen_port"));
            if (!strcmp(transport, "udp"))
                fprintf(fp, "  iifname \"%s\" ip daddr %s udp dport %d dnat to %s:%d\n",
                        iface, address, external, address, listen);
            else
                fprintf(fp, "  iifname \"%s\" ip daddr %s tcp dport %d redirect to :%d\n",
                        iface, address, external, listen);
        }
    }
    fprintf(fp, " }\n chain protect_internal { type filter hook input priority -5; policy accept;\n");
    fprintf(fp, "  tcp dport { 22021, 22022, 22023, 22080 } ct status dnat accept\n");
    fprintf(fp, "  tcp dport { 22021, 22022, 22023, 22080 } drop\n");
    fprintf(fp, "  udp dport 22053 ct status dnat accept\n");
    fprintf(fp, "  udp dport 22053 drop\n }\n}\n");
    if (fflush(fp) != 0 || fsync(fileno(fp)) != 0 || fclose(fp) != 0)
        return -1;
    return 0;
}

static int honeypot_nft_table_present(void)
{
    return honeypot_run("/usr/sbin/nft", "list", "table", "inet", HONEYPOT_TABLE, NULL) == 0;
}

static int honeypot_nft_delete(void)
{
    if (!honeypot_nft_table_present())
        return 0;
    return honeypot_run("/usr/sbin/nft", "delete", "table", "inet", HONEYPOT_TABLE, NULL);
}

static int honeypot_dummy_create(struct json_object *configs)
{
    int i;
    (void)honeypot_run("/sbin/ip", "link", "add", HONEYPOT_DEVICE, "type", "dummy");
    if (honeypot_run("/sbin/ip", "link", "set", HONEYPOT_DEVICE, "up", NULL) != 0)
        return -1;
    (void)honeypot_run("/sbin/ip", "addr", "flush", "dev", HONEYPOT_DEVICE, NULL);
    for (i = 0; i < (int)json_object_array_length(configs); i++) {
        char cidr[80];
        struct json_object *item = json_object_array_get_idx(configs, i);
        snprintf(cidr, sizeof(cidr), "%s/32", aegisxd_json_str(item, "address", ""));
        if (honeypot_run("/sbin/ip", "addr", "add", cidr, "dev", HONEYPOT_DEVICE) != 0)
            return -1;
    }
    return 0;
}

static int honeypot_interface_has_address(const char *iface, const char *expected)
{
    struct ifaddrs *all = NULL;
    int found = 0;

    if (getifaddrs(&all) != 0)
        return 0;
    for (struct ifaddrs *it = all; it; it = it->ifa_next) {
        char address[INET_ADDRSTRLEN];
        struct sockaddr_in *sin;

        if (!it->ifa_addr || it->ifa_addr->sa_family != AF_INET ||
            strcmp(it->ifa_name ? it->ifa_name : "", iface))
            continue;
        sin = (struct sockaddr_in *)it->ifa_addr;
        if (inet_ntop(AF_INET, &sin->sin_addr, address, sizeof(address)) &&
            !strcmp(address, expected)) {
            found = 1;
            break;
        }
    }
    freeifaddrs(all);
    return found;
}

static int honeypot_lan_addresses_delete(struct json_object *configs)
{
    int ok = 1;

    if (!configs || !json_object_is_type(configs, json_type_array))
        return 0;
    for (int i = 0; i < (int)json_object_array_length(configs); i++) {
        struct json_object *item = json_object_array_get_idx(configs, i);
        const char *address = aegisxd_json_str(item, "address", "");
        const char *iface = aegisxd_json_str(item, "interface", "");
        char cidr[80];

        if (!honeypot_ipv4_parse(address, NULL) || !honeypot_iface_ok(iface)) {
            ok = 0;
            continue;
        }
        snprintf(cidr, sizeof(cidr), "%s/32", address);
        if (honeypot_interface_has_address(iface, address) &&
            honeypot_run("/sbin/ip", "addr", "del", cidr, "dev", iface) != 0)
            ok = 0;
    }
    return ok ? 0 : -1;
}

static struct json_object *honeypot_runtime_configs_read(void)
{
    struct json_object *root = json_object_from_file(AEGISXD_HONEYPOT_RUNTIME_PATH);
    struct json_object *configs = NULL;

    if (!root || !json_object_is_type(root, json_type_object) ||
        !json_object_object_get_ex(root, "honeypots", &configs) ||
        !configs || !json_object_is_type(configs, json_type_array)) {
        if (root)
            json_object_put(root);
        return json_object_new_array();
    }
    json_object_get(configs);
    json_object_put(root);
    return configs;
}

static int honeypot_lan_addresses_apply(struct json_object *configs)
{
    struct json_object *previous = honeypot_runtime_configs_read();
    int ok = honeypot_lan_addresses_delete(previous) == 0;

    json_object_put(previous);
    for (int i = 0; i < (int)json_object_array_length(configs); i++) {
        struct json_object *item = json_object_array_get_idx(configs, i);
        const char *address = aegisxd_json_str(item, "address", "");
        const char *iface = aegisxd_json_str(item, "interface", "");
        char cidr[80];

        if (!honeypot_ipv4_parse(address, NULL) || !honeypot_iface_ok(iface))
            return -1;
        snprintf(cidr, sizeof(cidr), "%s/32", address);
        if (honeypot_run("/sbin/ip", "addr", "add", cidr, "dev", iface) != 0)
            return -1;
    }
    return ok ? 0 : -1;
}

static int honeypot_dummy_delete(void)
{
    if (!if_nametoindex(HONEYPOT_DEVICE))
        return 0;
    return honeypot_run("/sbin/ip", "link", "delete", HONEYPOT_DEVICE, NULL, NULL);
}

static int honeypot_process_action(const char *action)
{
    return honeypot_run("/usr/bin/dreamingwrt-init", action, "honeypotd", NULL, NULL, NULL);
}

static int honeypot_runtime_addresses_match(struct json_object *configs)
{
    /* Runtime readback must match every configured /32 before active=true. */
    struct ifaddrs *all = NULL;
    int matched = 0;
    int expected = (int)json_object_array_length(configs);

    if (getifaddrs(&all) != 0)
        return 0;
    for (int i = 0; i < expected; i++) {
        struct json_object *item = json_object_array_get_idx(configs, i);
        const char *expected_address = aegisxd_json_str(item, "address", "");
        const char *expected_iface = aegisxd_json_str(item, "interface", "");
        int found_dummy = 0, found_lan = 0;

        for (struct ifaddrs *it = all; it; it = it->ifa_next) {
            char address[INET_ADDRSTRLEN];
            struct sockaddr_in *sin;

            if (!it->ifa_addr || it->ifa_addr->sa_family != AF_INET)
                continue;
            sin = (struct sockaddr_in *)it->ifa_addr;
            if (inet_ntop(AF_INET, &sin->sin_addr, address, sizeof(address)) &&
                !strcmp(address, expected_address)) {
                if (!strcmp(it->ifa_name ? it->ifa_name : "", HONEYPOT_DEVICE))
                    found_dummy = 1;
                if (!strcmp(it->ifa_name ? it->ifa_name : "", expected_iface))
                    found_lan = 1;
            }
        }
        if (found_dummy && found_lan)
            matched++;
    }
    freeifaddrs(all);
    return matched == expected;
}

static int aegisxd_honeypot_network_apply_atomic(struct json_object *configs)
{
    char tmp[AEGISXD_MAX_PATH + 16];
    int count = (int)json_object_array_length(configs);
    int rc = -1;

    snprintf(tmp, sizeof(tmp), "%s.tmp", AEGISXD_HONEYPOT_NFT_PATH);
    if (!count) {
        int cleanup_ok = 1;

        if (honeypot_process_action("stop") != 0)
            cleanup_ok = 0;
        {
            struct json_object *previous = honeypot_runtime_configs_read();
            if (honeypot_lan_addresses_delete(previous) != 0)
                cleanup_ok = 0;
            json_object_put(previous);
        }
        if (honeypot_nft_delete() != 0)
            cleanup_ok = 0;
        if (honeypot_dummy_delete() != 0)
            cleanup_ok = 0;
        unlink(AEGISXD_HONEYPOT_ACTIVE_PATH);
        if (honeypot_write_runtime(configs) != 0)
            cleanup_ok = 0;
        return cleanup_ok ? 0 : -1;
    }
    int replace_existing = honeypot_nft_table_present();

    if (!aegisxd_honeypot_binary_available() ||
        honeypot_write_nft(configs, tmp, replace_existing) != 0)
        goto out;
    if (honeypot_run("/usr/sbin/nft", "-c", "-f", tmp, NULL, NULL) != 0)
        goto out;
    if (honeypot_dummy_create(configs) != 0)
        goto out;
    if (honeypot_lan_addresses_apply(configs) != 0)
        goto out;
    if (honeypot_run("/usr/sbin/nft", "-f", tmp, NULL, NULL, NULL) != 0)
        goto out;
    if (rename(tmp, AEGISXD_HONEYPOT_NFT_PATH) != 0 || honeypot_write_runtime(configs) != 0)
        goto out;
    {
        char state[192];
        snprintf(state, sizeof(state),
                 "{\"active\":true,\"applied_at\":%" PRId64 ",\"nft_table\":\"%s\"}\n",
                 aegisxd_now_s(), HONEYPOT_TABLE);
        if (honeypot_write_atomic(AEGISXD_HONEYPOT_ACTIVE_PATH, state, 0640) != 0)
            goto out;
    }
    if (honeypot_process_action("restart") != 0 || !honeypot_process_running() ||
        !honeypot_nft_table_present() || !honeypot_runtime_addresses_match(configs))
        goto out;
    rc = 0;
out:
    if (rc != 0) {
        (void)honeypot_process_action("stop");
        (void)honeypot_nft_delete();
        (void)honeypot_lan_addresses_delete(configs);
        (void)honeypot_dummy_delete();
        unlink(AEGISXD_HONEYPOT_ACTIVE_PATH);
    }
    unlink(tmp);
    return rc;
}

static int honeypot_apply_current(void)
{
    struct json_object *configs = honeypot_config_array(1);
    int rc = aegisxd_honeypot_network_apply_atomic(configs);

    json_object_put(configs);
    return rc;
}

int aegisxd_honeypot_reconcile(void)
{
    return honeypot_apply_current();
}

int aegisxd_honeypot_binary_available(void)
{
    return access(AEGISXD_HONEYPOT_BINARY, X_OK) == 0;
}

static int honeypot_config_enabled(void)
{
    sqlite3_stmt *st = aegisxd_config_prepare(
        "SELECT COUNT(*) FROM aegis_honeypots WHERE enabled=1");
    int count = 0;
    if (st && sqlite3_step(st) == SQLITE_ROW)
        count = sqlite3_column_int(st, 0);
    if (st)
        sqlite3_finalize(st);
    return count > 0;
}

static int honeypot_process_running(void)
{
    DIR *dir = opendir("/proc");
    struct dirent *entry;
    int running = 0;

    while (dir && (entry = readdir(dir))) {
        char path[128], target[AEGISXD_MAX_PATH], *tail = NULL;
        ssize_t n;
        long pid = strtol(entry->d_name, &tail, 10);
        if (!tail || *tail || pid <= 1)
            continue;
        snprintf(path, sizeof(path), "/proc/%ld/exe", pid);
        n = readlink(path, target, sizeof(target) - 1);
        if (n <= 0)
            continue;
        target[n] = '\0';
        if (!strcmp(target, AEGISXD_HONEYPOT_BINARY) ||
            strstr(target, "/dreamingwrt-honeypotd")) {
            running = kill((pid_t)pid, 0) == 0;
            if (running)
                break;
        }
    }
    if (dir)
        closedir(dir);
    return running;
}

int aegisxd_honeypot_active(void)
{
    struct json_object *configs = honeypot_config_array(1);
    int active = aegisxd_honeypot_binary_available() && honeypot_config_enabled() &&
           honeypot_process_running() && if_nametoindex(HONEYPOT_DEVICE) &&
           honeypot_runtime_addresses_match(configs) && honeypot_nft_table_present() &&
           access(AEGISXD_HONEYPOT_RUNTIME_PATH, R_OK) == 0 &&
           access(AEGISXD_HONEYPOT_ACTIVE_PATH, R_OK) == 0;

    json_object_put(configs);
    return active;
}

int aegisxd_honeypot_hit_count(void)
{
    sqlite3_stmt *st = aegisxd_prepare(
        "SELECT COALESCE(SUM(occurrence_count),0) FROM aegis_events WHERE policy_type='honeypot'");
    int count = 0;
    if (st && sqlite3_step(st) == SQLITE_ROW) count = sqlite3_column_int(st, 0);
    if (st) sqlite3_finalize(st);
    return count;
}

struct json_object *aegisxd_honeypot_runtime_json(void)
{
    struct json_object *runtime = json_object_new_object();
    int binary = aegisxd_honeypot_binary_available();
    int active = aegisxd_honeypot_active();
    int configured = honeypot_config_enabled();
    json_object_object_add(runtime, "supported", json_object_new_boolean(binary));
    json_object_object_add(runtime, "active", json_object_new_boolean(active));
    json_object_object_add(runtime, "honeypot_runtime_active", json_object_new_boolean(active));
    json_object_object_add(runtime, "honeypot_config_active", json_object_new_boolean(configured));
    json_object_object_add(runtime, "honeypot_process_running",
                           json_object_new_boolean(honeypot_process_running()));
    aegisxd_json_add_string(runtime, "honeypot_runtime_state", active ? "running" : "stopped");
    aegisxd_json_add_string(runtime, "state", active ? "running" : "stopped");
    aegisxd_json_add_string(runtime, "reason", active ? "" :
        (binary ? "honeypot_not_enabled_or_runtime_incomplete" : "honeypotd_binary_missing"));
    aegisxd_json_add_string(runtime, "binary", binary ? AEGISXD_HONEYPOT_BINARY : "");
    aegisxd_json_add_string(runtime, "runtime_config", AEGISXD_HONEYPOT_RUNTIME_PATH);
    aegisxd_json_add_string(runtime, "nft_table", HONEYPOT_TABLE);
    aegisxd_json_add_string(runtime, "dummy_device", HONEYPOT_DEVICE);
    json_object_object_add(runtime, "hits", json_object_new_int(aegisxd_honeypot_hit_count()));
    return runtime;
}

struct json_object *aegisxd_honeypot_get_json(void)
{
    struct json_object *resp = json_object_new_object();
    struct json_object *cap = json_object_new_object();
    json_object_object_add(resp, "ok", json_object_new_boolean(1));
    aegisxd_json_add_string(resp, "source", "config.db:aegis_honeypots+aegisxd_runtime");
    json_object_object_add(resp, "items", honeypot_config_array(0));
    json_object_object_add(resp, "runtime", aegisxd_honeypot_runtime_json());
    json_object_object_add(cap, "config", json_object_new_boolean(1));
    json_object_object_add(cap, "validate", json_object_new_boolean(1));
    json_object_object_add(cap, "guarded_apply", json_object_new_boolean(1));
    json_object_object_add(cap, "rollback", json_object_new_boolean(1));
    json_object_object_add(cap, "event_ingest", json_object_new_boolean(1));
    json_object_object_add(cap, "credential_plaintext_storage", json_object_new_boolean(0));
    json_object_object_add(cap, "ssh", json_object_new_boolean(1));
    json_object_object_add(cap, "telnet", json_object_new_boolean(1));
    json_object_object_add(cap, "http", json_object_new_boolean(1));
    json_object_object_add(cap, "ftp", json_object_new_boolean(1));
    json_object_object_add(cap, "dns", json_object_new_boolean(1));
    json_object_object_add(cap, "smb", json_object_new_boolean(0));
    json_object_object_add(cap, "rdp", json_object_new_boolean(0));
    json_object_object_add(cap, "redis", json_object_new_boolean(0));
    json_object_object_add(cap, "max_addresses_per_network",
                           json_object_new_int(HONEYPOT_MAX_ADDRESSES_PER_NETWORK));
    json_object_object_add(cap, "wan_exposure", json_object_new_boolean(0));
    json_object_object_add(resp, "capabilities", cap);
    return resp;
}

static struct json_object *honeypot_validate_body(struct json_object *body, int check_runtime)
{
    struct json_object *resp = json_object_new_object();
    struct json_object *blockers = json_object_new_array();
    struct json_object *services = NULL;
    const char *id = aegisxd_json_str(body, "id", "");
    const char *network_id = aegisxd_json_str(body, "network_id", "");
    const char *address = aegisxd_json_str(body, "address", "");
    const char *profile = aegisxd_json_str(body, "profile", "linux_server");
    const char *error = NULL;
    char iface[IFNAMSIZ] = "", gateway[64] = "", start[64] = "", end[64] = "";
    int prefix = 0;

    if (id[0] && !honeypot_id_ok(id)) error = "invalid_honeypot_id";
    else if (!honeypot_id_ok(network_id)) error = "invalid_network_id";
    else if (!honeypot_profile_ok(profile)) error = "invalid_honeypot_profile";
    else if (honeypot_network_address_count(network_id, id) >= HONEYPOT_MAX_ADDRESSES_PER_NETWORK)
        error = "honeypot_network_address_limit_reached";
    else if (honeypot_network_load(network_id, iface, sizeof(iface), gateway, sizeof(gateway),
                                   &prefix, start, sizeof(start), end, sizeof(end)) != 0)
        error = "honeypot_network_not_found";
    else
        (void)honeypot_validate_address(address, gateway, prefix, start, end, id, &error);
    services = !error ? honeypot_normalize_services(body, profile, &error) : NULL;
    if (check_runtime && !error && !aegisxd_honeypot_binary_available())
        error = "honeypotd_binary_missing";
    if (error)
        json_object_array_add(blockers, json_object_new_string(error));
    json_object_object_add(resp, "ok", json_object_new_boolean(!error));
    json_object_object_add(resp, "valid", json_object_new_boolean(!error));
    json_object_object_add(resp, "changed", json_object_new_boolean(0));
    json_object_object_add(resp, "dataplane_changed", json_object_new_boolean(0));
    json_object_object_add(resp, "dry_run", json_object_new_boolean(1));
    json_object_object_add(resp, "confirm_required", json_object_new_boolean(1));
    json_object_object_add(resp, "management_port_conflict", json_object_new_boolean(0));
    json_object_object_add(resp, "wan_exposure", json_object_new_boolean(0));
    json_object_object_add(resp, "blockers", blockers);
    aegisxd_json_add_string(resp, "network_id", network_id);
    aegisxd_json_add_string(resp, "interface", iface);
    aegisxd_json_add_string(resp, "gateway", gateway);
    json_object_object_add(resp, "prefix", json_object_new_int(prefix));
    aegisxd_json_add_string(resp, "address", address);
    aegisxd_json_add_string(resp, "profile", profile);
    if (services) json_object_object_add(resp, "services", services);
    if (error) aegisxd_json_add_string(resp, "error", error);
    return resp;
}

struct json_object *aegisxd_honeypot_validate_json(struct json_object *body)
{
    return honeypot_validate_body(body, 1);
}

struct json_object *aegisxd_honeypot_set_json(struct json_object *body)
{
    struct json_object *validation = honeypot_validate_body(body, 1);
    struct json_object *previous_config = NULL;
    struct json_object *services = NULL, *blockers = NULL;
    const char *id = aegisxd_json_str(body, "id", "");
    const char *name = aegisxd_json_str(body, "name", "Honeypot");
    const char *network_id = aegisxd_json_str(body, "network_id", "");
    const char *address = aegisxd_json_str(body, "address", "");
    const char *profile = aegisxd_json_str(body, "profile", "linux_server");
    const char *iface = aegisxd_json_str(validation, "interface", "");
    int enabled = aegisxd_json_bool(body, "enabled", 1);
    int confirm = aegisxd_json_bool(body, "confirm", 0);
    int max_connections = json_object_get_int(json_object_object_get(body, "max_connections"));
    int max_per_source = json_object_get_int(json_object_object_get(body, "max_per_source"));
    int capture_bytes = json_object_get_int(json_object_object_get(body, "capture_bytes"));
    int idle_timeout = json_object_get_int(json_object_object_get(body, "idle_timeout"));
    int session_timeout = json_object_get_int(json_object_object_get(body, "session_timeout"));
    sqlite3_stmt *st;
    int rc;

    if (!max_connections) max_connections = 128;
    if (!max_per_source) max_per_source = 8;
    if (!capture_bytes) capture_bytes = 4096;
    if (!idle_timeout) idle_timeout = 20;
    if (!session_timeout) session_timeout = 60;
    if (!json_object_get_boolean(json_object_object_get(validation, "ok")))
        return validation;
    if (!id[0] || !honeypot_id_ok(id) || !honeypot_text_ok(name, 128, 1) ||
        max_connections < 1 || max_connections > 128 || max_per_source < 1 || max_per_source > 8 ||
        capture_bytes < 256 || capture_bytes > 4096 || idle_timeout < 5 || idle_timeout > 60 ||
        session_timeout < idle_timeout || session_timeout > 120) {
        json_object_put(validation);
        return aegisxd_error("invalid_honeypot_config", "honeypot config contains invalid fields");
    }
    if (!confirm)
        return validation;
    previous_config = honeypot_config_array(1);
    json_object_object_get_ex(validation, "services", &services);
    if (!services) {
        json_object_put(previous_config);
        json_object_put(validation);
        return aegisxd_error("invalid_services", "services are required");
    }
    if (sqlite3_exec(g_aegisxd_config_db, "BEGIN IMMEDIATE", NULL, NULL, NULL) != SQLITE_OK) {
        json_object_put(previous_config);
        json_object_put(validation);
        return aegisxd_error("storage_error", "honeypot transaction could not start");
    }
    st = aegisxd_config_prepare(
        "INSERT INTO aegis_honeypots(id,name,enabled,network_id,interface,address,profile,services_json,"
        "max_connections,max_per_source,capture_bytes,idle_timeout,session_timeout,apply_state,last_error,created_at,updated_at) "
        "VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,'pending','',?14,?14) "
        "ON CONFLICT(id) DO UPDATE SET name=excluded.name,enabled=excluded.enabled,network_id=excluded.network_id,"
        "interface=excluded.interface,address=excluded.address,profile=excluded.profile,services_json=excluded.services_json,"
        "max_connections=excluded.max_connections,max_per_source=excluded.max_per_source,capture_bytes=excluded.capture_bytes,"
        "idle_timeout=excluded.idle_timeout,session_timeout=excluded.session_timeout,apply_state='pending',last_error='',"
        "updated_at=excluded.updated_at");
    if (!st) goto rollback;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT); sqlite3_bind_text(st, 2, name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 3, enabled); sqlite3_bind_text(st, 4, network_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 5, iface, -1, SQLITE_TRANSIENT); sqlite3_bind_text(st, 6, address, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 7, profile, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 8, json_object_to_json_string_ext(services, JSON_C_TO_STRING_PLAIN), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 9, max_connections); sqlite3_bind_int(st, 10, max_per_source);
    sqlite3_bind_int(st, 11, capture_bytes); sqlite3_bind_int(st, 12, idle_timeout);
    sqlite3_bind_int(st, 13, session_timeout); sqlite3_bind_int64(st, 14, aegisxd_now_s());
    rc = sqlite3_step(st); sqlite3_finalize(st);
    if (rc != SQLITE_DONE || honeypot_apply_current() != 0) goto rollback;
    st = aegisxd_config_prepare("UPDATE aegis_honeypots SET apply_state=?1,last_error='',updated_at=?2 WHERE id=?3");
    if (!st) goto rollback;
    sqlite3_bind_text(st, 1, enabled ? "active" : "disabled", -1, SQLITE_STATIC);
    sqlite3_bind_int64(st, 2, aegisxd_now_s()); sqlite3_bind_text(st, 3, id, -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(st); sqlite3_finalize(st);
    if (rc != SQLITE_DONE || sqlite3_exec(g_aegisxd_config_db, "COMMIT", NULL, NULL, NULL) != SQLITE_OK)
        goto rollback;
    json_object_put(validation);
    validation = aegisxd_honeypot_get_json();
    json_object_object_add(validation, "changed", json_object_new_boolean(1));
    json_object_object_add(validation, "dataplane_changed", json_object_new_boolean(1));
    aegisxd_json_add_string(validation, "id", id);
    json_object_put(previous_config);
    return validation;
rollback:
    sqlite3_exec(g_aegisxd_config_db, "ROLLBACK", NULL, NULL, NULL);
    rc = previous_config ? aegisxd_honeypot_network_apply_atomic(previous_config) : -1;
    if (previous_config)
        json_object_put(previous_config);
    json_object_object_get_ex(validation, "blockers", &blockers);
    if (blockers) json_object_array_add(blockers, json_object_new_string(
        rc == 0 ? "honeypot_runtime_apply_failed" : "apply_failed_rollback_failed"));
    json_object_object_add(validation, "ok", json_object_new_boolean(0));
    json_object_object_add(validation, "valid", json_object_new_boolean(0));
    json_object_object_add(validation, "rollback_ok", json_object_new_boolean(rc == 0));
    aegisxd_json_add_string(validation, "error",
                            rc == 0 ? "honeypot_runtime_apply_failed" : "apply_failed_rollback_failed");
    return validation;
}

struct json_object *aegisxd_honeypot_delete_json(struct json_object *body)
{
    const char *id = aegisxd_json_str(body, "id", "");
    int confirm = aegisxd_json_bool(body, "confirm", 0), exists = 0;
    sqlite3_stmt *st;
    struct json_object *resp, *previous_config = NULL;
    if (!honeypot_id_ok(id)) return aegisxd_error("invalid_honeypot_id", "honeypot id is invalid");
    st = aegisxd_config_prepare("SELECT 1 FROM aegis_honeypots WHERE id=?1");
    if (st) { sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT); exists = sqlite3_step(st) == SQLITE_ROW; sqlite3_finalize(st); }
    if (!exists) return aegisxd_error("honeypot_not_found", "honeypot does not exist");
    if (!confirm) {
        resp = json_object_new_object(); json_object_object_add(resp, "ok", json_object_new_boolean(1));
        json_object_object_add(resp, "confirm_required", json_object_new_boolean(1));
        json_object_object_add(resp, "changed", json_object_new_boolean(0));
        json_object_object_add(resp, "dataplane_changed", json_object_new_boolean(0)); aegisxd_json_add_string(resp, "id", id);
        return resp;
    }
    if (sqlite3_exec(g_aegisxd_config_db, "BEGIN IMMEDIATE", NULL, NULL, NULL) != SQLITE_OK)
        return aegisxd_error("storage_error", "honeypot transaction could not start");
    previous_config = honeypot_config_array(1);
    st = aegisxd_config_prepare("DELETE FROM aegis_honeypots WHERE id=?1");
    if (!st) goto rollback_delete;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    exists = sqlite3_step(st) == SQLITE_DONE; sqlite3_finalize(st);
    if (!exists || honeypot_apply_current() != 0 ||
        sqlite3_exec(g_aegisxd_config_db, "COMMIT", NULL, NULL, NULL) != SQLITE_OK)
        goto rollback_delete;
    resp = aegisxd_honeypot_get_json();
    json_object_object_add(resp, "changed", json_object_new_boolean(1));
    json_object_object_add(resp, "dataplane_changed", json_object_new_boolean(1));
    aegisxd_json_add_string(resp, "id", id); aegisxd_json_add_string(resp, "action", "deleted");
    json_object_put(previous_config);
    return resp;
rollback_delete:
    sqlite3_exec(g_aegisxd_config_db, "ROLLBACK", NULL, NULL, NULL);
    exists = previous_config ? aegisxd_honeypot_network_apply_atomic(previous_config) : -1;
    if (previous_config)
        json_object_put(previous_config);
    resp = aegisxd_error(exists == 0 ? "honeypot_delete_apply_failed" : "apply_failed_rollback_failed",
                         exists == 0 ? "honeypot delete could not be applied" :
                                       "honeypot delete failed and the previous runtime could not be restored");
    json_object_object_add(resp, "rollback_ok", json_object_new_boolean(exists == 0));
    return resp;
}

static void honeypot_source_mac(const char *source_ip, char *mac, size_t mac_len)
{
    FILE *fp = fopen("/proc/net/arp", "r");
    char line[512], ip[64], hw[64], flags[64], found[64], mask[64], dev[64];
    mac[0] = '\0';
    if (!fp) return;
    while (fgets(line, sizeof(line), fp))
        if (sscanf(line, "%63s %63s %63s %63s %63s %63s", ip, hw, flags, found, mask, dev) == 6 &&
            !strcmp(ip, source_ip)) {
            /* found[] is scanned at width 63 but a real MAC is 17 characters;
             * anything that does not fit the caller's field is not a MAC, so
             * leave the field empty rather than store a truncated one. */
            if (jmx_strbuf_copy(mac, mac_len, found) != 0)
                mac[0] = '\0';
            break;
        }
    fclose(fp);
}

static int honeypot_token_equal(const char *provided)
{
    unsigned char difference = 0;
    size_t expected_len = strlen(g_honeypot_ingest_token);
    size_t provided_len = provided ? strlen(provided) : 0;

    if (expected_len != 64 || provided_len != expected_len)
        return 0;
    for (size_t i = 0; i < expected_len; i++)
        difference |= (unsigned char)(provided[i] ^ g_honeypot_ingest_token[i]);
    return difference == 0;
}

static int honeypot_event_service_enabled(const char *destination_ip, const char *service,
                                          const char *profile, char *interface,
                                          size_t interface_len)
{
    sqlite3_stmt *st = aegisxd_config_prepare(
        "SELECT interface,profile,services_json FROM aegis_honeypots "
        "WHERE enabled=1 AND address=?1 LIMIT 1");
    int enabled = 0;

    if (!st)
        return 0;
    sqlite3_bind_text(st, 1, destination_ip, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW) {
        const char *stored_profile = aegisxd_sqlite_text(st, 1, "");
        struct json_object *services = json_tokener_parse(aegisxd_sqlite_text(st, 2, "[]"));

        if (!strcmp(stored_profile, profile) && services &&
            json_object_is_type(services, json_type_array)) {
            for (int i = 0; i < (int)json_object_array_length(services); i++) {
                struct json_object *entry = json_object_array_get_idx(services, i);

                if (entry && json_object_is_type(entry, json_type_string) &&
                    !strcmp(json_object_get_string(entry), service)) {
                    snprintf(interface, interface_len, "%s", aegisxd_sqlite_text(st, 0, ""));
                    enabled = interface[0] != '\0';
                    break;
                }
            }
        }
        if (services)
            json_object_put(services);
    }
    sqlite3_finalize(st);
    return enabled;
}

struct json_object *aegisxd_honeypot_event_ingest(struct json_object *body)
{
    const char *event_type = aegisxd_json_str(body, "event_type", "");
    const char *source_ip = aegisxd_json_str(body, "source_ip", "");
    const char *destination_ip = aegisxd_json_str(body, "destination_ip", "");
    const char *transport = aegisxd_json_str(body, "transport", "");
    const char *service = aegisxd_json_str(body, "service", "");
    const char *profile = aegisxd_json_str(body, "profile", "");
    const char *stage = aegisxd_json_str(body, "stage", "connect");
    const char *ingest_token = aegisxd_json_str(body, "ingest_token", "");
    struct json_object *payload = NULL, *meta = json_object_new_object();
    struct json_object *safe_payload = json_object_new_object();
    sqlite3_stmt *st;
    char interface[IFNAMSIZ] = "", mac[32] = "";
    int source_port = json_object_get_int(json_object_object_get(body, "source_port"));
    int destination_port = json_object_get_int(json_object_object_get(body, "destination_port"));
    int64_t timestamp_ms = json_object_get_int64(json_object_object_get(body, "timestamp_ms"));
    int recent = 0, rc;
    int64_t now = aegisxd_now_s();
    char aggregate_key[512];
    const char *risk;
    const struct honeypot_service *service_def;
    const char *wire = json_object_to_json_string_ext(body, JSON_C_TO_STRING_PLAIN);
    static const char *safe_keys[] = { "username", "password_present", "password_length", "password_sha256", "method", "uri",
        "host", "user_agent", "qname", "qtype", "rcode", "client_banner", "command", NULL };
    int i;

    service_def = honeypot_service_find(service);
    if (!wire || strlen(wire) > AEGISXD_HONEYPOT_MAX_EVENT_BYTES ||
        strcmp(event_type, "honeypot_hit") || timestamp_ms <= 0 || !honeypot_token_equal(ingest_token) ||
        llabs(timestamp_ms / 1000 - now) > 300 ||
        !honeypot_ipv4_parse(source_ip, NULL) || !honeypot_ipv4_parse(destination_ip, NULL) ||
        (!strcmp(transport, "tcp") == !strcmp(transport, "udp")) ||
        !service_def || strcmp(service_def->transport, transport) ||
        service_def->external_port != destination_port || !honeypot_profile_ok(profile) ||
        source_port < 1 || source_port > 65535 || destination_port < 1 || destination_port > 65535 ||
        !honeypot_text_ok(stage, 64, 1))
        goto invalid;
    if (!honeypot_event_service_enabled(destination_ip, service, profile,
                                         interface, sizeof(interface)))
        goto invalid;
    json_object_object_get_ex(body, "payload", &payload);
    if (payload && json_object_is_type(payload, json_type_object))
        for (i = 0; safe_keys[i]; i++) {
            struct json_object *value = NULL;
            if (json_object_object_get_ex(payload, safe_keys[i], &value) && value) {
                const char *serialized = json_object_to_json_string_ext(value, JSON_C_TO_STRING_PLAIN);
                if (serialized && strlen(serialized) <= 1024)
                    json_object_object_add(safe_payload, safe_keys[i], json_object_get(value));
            }
        }
    json_object_object_add(meta, "schema_version", json_object_new_int(1));
    json_object_object_add(meta, "producer_timestamp_ms", json_object_new_int64(timestamp_ms));
    aegisxd_json_add_string(meta, "service", service); aegisxd_json_add_string(meta, "profile", profile);
    aegisxd_json_add_string(meta, "stage", stage); json_object_object_add(meta, "payload", safe_payload);
    honeypot_source_mac(source_ip, mac, sizeof(mac));
    st = aegisxd_prepare("SELECT COALESCE(SUM(occurrence_count),0) FROM aegis_events "
                         "WHERE policy_type='honeypot' AND source_ip=?1 AND ts>=?2");
    if (st) {
        sqlite3_bind_text(st, 1, source_ip, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 2, now - 60);
        if (sqlite3_step(st) == SQLITE_ROW)
            recent = sqlite3_column_int(st, 0);
        sqlite3_finalize(st);
    }
    risk = recent >= 3 ? "critical" : (!strcmp(stage, "credentials") || strcmp(stage, "connect")) ? "high" : "medium";
    snprintf(aggregate_key, sizeof(aggregate_key), "honeypot|%s|%s|%s|%s",
             source_ip, destination_ip, service, stage);
    st = aegisxd_prepare(
        "UPDATE aegis_events SET ts=?1,last_seen=?1,occurrence_count=occurrence_count+1,risk=?2,"
        "source_port=?3,meta_json=?4 WHERE id=(SELECT id FROM aegis_events WHERE policy_type='honeypot' "
        "AND flow_id=?5 AND last_seen>=?6 ORDER BY id DESC LIMIT 1)");
    if (st) {
        sqlite3_bind_int64(st, 1, now);
        sqlite3_bind_text(st, 2, risk, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 3, source_port);
        sqlite3_bind_text(st, 4, json_object_to_json_string_ext(meta, JSON_C_TO_STRING_PLAIN),
                          -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 5, aggregate_key, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 6, now - HONEYPOT_EVENT_DEDUPE_S);
        rc = sqlite3_step(st);
        recent = sqlite3_changes(g_aegisxd_db);
        sqlite3_finalize(st);
        if (rc != SQLITE_DONE) {
            json_object_put(meta);
            return aegisxd_error("honeypot_event_save_failed", "honeypot event aggregation failed");
        }
        if (recent > 0) {
            json_object_put(meta);
            meta = json_object_new_object();
            json_object_object_add(meta, "ok", json_object_new_boolean(1));
            json_object_object_add(meta, "stored", json_object_new_boolean(1));
            json_object_object_add(meta, "aggregated", json_object_new_boolean(1));
            aegisxd_json_add_string(meta, "risk", risk);
            return meta;
        }
    }
    st = aegisxd_prepare(
        "INSERT INTO aegis_events(ts,event_type,level,action,policy_id,policy_name,policy_type,rule_id,rule_name,"
        "risk,risk_category,source_ip,source_mac,source_port,destination_ip,destination_port,protocol,in_interface,"
        "reason,source,flow_id,occurrence_count,first_seen,last_seen,meta_json) "
        "VALUES(?1,'honeypot_hit','warning','alert','honeypot','Internal Honeypot','honeypot',"
        "?2,?3,?4,'lateral_movement',?5,?6,?7,?8,?9,?10,?11,'dark_address_service_access',"
        "'aegisxd.honeypot',?12,1,?1,?1,?13)");
    if (!st) { json_object_put(meta); return aegisxd_error("storage_error", "honeypot event storage unavailable"); }
    sqlite3_bind_int64(st, 1, now); sqlite3_bind_text(st, 2, service, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, service, -1, SQLITE_TRANSIENT); sqlite3_bind_text(st, 4, risk, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 5, source_ip, -1, SQLITE_TRANSIENT); sqlite3_bind_text(st, 6, mac, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 7, source_port); sqlite3_bind_text(st, 8, destination_ip, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 9, destination_port); sqlite3_bind_text(st, 10, transport, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 11, interface, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 12, aggregate_key, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 13, json_object_to_json_string_ext(meta, JSON_C_TO_STRING_PLAIN), -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(st); sqlite3_finalize(st); json_object_put(meta);
    if (rc != SQLITE_DONE) return aegisxd_error("honeypot_event_save_failed", "honeypot event could not be saved");
    meta = json_object_new_object(); json_object_object_add(meta, "ok", json_object_new_boolean(1));
    json_object_object_add(meta, "stored", json_object_new_boolean(1));
    json_object_object_add(meta, "aggregated", json_object_new_boolean(0));
    aegisxd_json_add_string(meta, "risk", risk);
    return meta;
invalid:
    json_object_put(meta); json_object_put(safe_payload);
    return aegisxd_error("invalid_honeypot_event", "honeypot event failed validation");
}

struct json_object *aegisxd_honeypot_events_json(struct json_object *body)
{
    struct json_object *resp = json_object_new_object(), *items = json_object_new_array();
    int limit = json_object_get_int(json_object_object_get(body, "limit"));
    int offset = json_object_get_int(json_object_object_get(body, "offset"));
    sqlite3_stmt *st;
    if (limit < 1)
        limit = 100;
    if (limit > 500)
        limit = 500;
    if (offset < 0) offset = 0;
    st = aegisxd_prepare("SELECT id,ts,risk,source_ip,source_mac,source_port,destination_ip,destination_port,protocol,"
                         "in_interface,occurrence_count,first_seen,last_seen,meta_json "
                         "FROM aegis_events WHERE policy_type='honeypot' AND event_type='honeypot_hit' "
                         "ORDER BY ts DESC,id DESC LIMIT ?1 OFFSET ?2");
    if (st) { sqlite3_bind_int(st, 1, limit); sqlite3_bind_int(st, 2, offset); }
    while (st && sqlite3_step(st) == SQLITE_ROW) {
        struct json_object *item = json_object_new_object();
        struct json_object *meta = json_tokener_parse(aegisxd_sqlite_text(st, 13, "{}"));
        json_object_object_add(item, "id", json_object_new_int64(sqlite3_column_int64(st, 0)));
        json_object_object_add(item, "timestamp", json_object_new_int64(sqlite3_column_int64(st, 1)));
        aegisxd_json_add_string(item, "risk", aegisxd_sqlite_text(st, 2, ""));
        aegisxd_json_add_string(item, "source_ip", aegisxd_sqlite_text(st, 3, ""));
        aegisxd_json_add_string(item, "source_mac", aegisxd_sqlite_text(st, 4, ""));
        json_object_object_add(item, "source_port", json_object_new_int(sqlite3_column_int(st, 5)));
        aegisxd_json_add_string(item, "destination_ip", aegisxd_sqlite_text(st, 6, ""));
        json_object_object_add(item, "destination_port", json_object_new_int(sqlite3_column_int(st, 7)));
        aegisxd_json_add_string(item, "transport", aegisxd_sqlite_text(st, 8, ""));
        aegisxd_json_add_string(item, "interface", aegisxd_sqlite_text(st, 9, ""));
        json_object_object_add(item, "occurrence_count", json_object_new_int(sqlite3_column_int(st, 10)));
        json_object_object_add(item, "first_seen", json_object_new_int64(sqlite3_column_int64(st, 11)));
        json_object_object_add(item, "last_seen", json_object_new_int64(sqlite3_column_int64(st, 12)));
        json_object_object_add(item, "meta", meta ? meta : json_object_new_object());
        json_object_array_add(items, item);
    }
    if (st) sqlite3_finalize(st);
    json_object_object_add(resp, "ok", json_object_new_boolean(1)); json_object_object_add(resp, "items", items);
    {
        sqlite3_stmt *count_st = aegisxd_prepare(
            "SELECT COUNT(*) FROM aegis_events WHERE policy_type='honeypot' "
            "AND event_type='honeypot_hit'");
        int total = 0;

        if (count_st && sqlite3_step(count_st) == SQLITE_ROW)
            total = sqlite3_column_int(count_st, 0);
        if (count_st)
            sqlite3_finalize(count_st);
        json_object_object_add(resp, "total", json_object_new_int(total));
    }
    json_object_object_add(resp, "total_occurrences",
                           json_object_new_int(aegisxd_honeypot_hit_count()));
    json_object_object_add(resp, "limit", json_object_new_int(limit));
    json_object_object_add(resp, "offset", json_object_new_int(offset));
    return resp;
}
