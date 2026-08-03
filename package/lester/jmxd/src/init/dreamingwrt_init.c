// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * dreamingwrt-init - small supervisor and CLI for split DreamingWrt daemons.
 *
 * procd starts "dreamingwrt-init run"; human/console use talks to it through
 * a local Unix socket. The fallback status path scans /proc so smoke tests are
 * useful before switching the boot chain over to this supervisor.
 */
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <sqlite3.h>

#define DWRT_INIT_VERSION "0.1.5"
#define DWRT_INIT_SOCKET "/var/run/dreamingwrt-init.sock"
#define DWRT_INIT_SELF_PATH "/usr/bin/dreamingwrt-init"
#define DWRT_INIT_CONFIG "/etc/dreamingwrt/init.json"
#define DWRT_APP_DB "/etc/dreamingwrt/apid.db"
#define DWRT_CONFIG_DB "/etc/dreamingwrt/config.db"
#define DWRT_NETWORK_CONFIG "/etc/config/network"
#define DWRT_DHCP_CONFIG "/etc/config/dhcp"
#define DWRT_FIREWALL_CONFIG "/etc/config/firewall"
#define DWRT_NETWORK_BACKUP_DIR "/etc/dreamingwrt/network-backup"
#define DWRT_PERSIST_INIT "/etc/init.d/dreamingwrt-persist"
#define DWRT_PERSIST_MOUNT "/etc/dreamingwrt"
#define DWRT_PERSIST_WAIT_SECONDS 60
#define DWRT_AUTO_ROLLBACK_POLL_SEC 5
#define DWRT_MAX_RESPAWN_BACKOFF_SEC 60
#define DWRT_WARN_FS_PCT 85
#define DWRT_CRIT_FS_PCT 95
#define DWRT_WARN_DB_BYTES (256ULL * 1024ULL * 1024ULL)
#define DWRT_CRIT_DB_BYTES (1024ULL * 1024ULL * 1024ULL)
#define DWRT_WARN_WAL_BYTES (64ULL * 1024ULL * 1024ULL)
#define DWRT_CRIT_WAL_BYTES (256ULL * 1024ULL * 1024ULL)
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

#include "config_restore.h"
#include "system_db_sync.h"

enum prepare_flags {
    PREP_NONE = 0,
    PREP_CORE = 1 << 0,
    PREP_AUDIT = 1 << 1,
};

struct component {
    const char *name;
    const char *path;
    const char *alias_name;
    const char *alias_path;
    const char *args[4];
    const char *env_defaults[8];
    int enabled;
    int critical;
    int stop_timeout_sec;
    int prepare_flags;
    pid_t pid;
    int desired;
    time_t next_respawn_at;
    time_t started_at;
    time_t last_exit_at;
    int last_exit_status;
    int last_exit_code;
    int last_exit_signal;
    int restart_count;
    int crash_count;
    int backoff_sec;
};

struct outbuf {
    char *data;
    size_t len;
    size_t cap;
};

struct fs_usage {
    const char *name;
    const char *path;
    unsigned long long total_bytes;
    unsigned long long used_bytes;
    unsigned long long avail_bytes;
    int used_pct;
    int ok;
};

#define DWRT_STORAGE_SCAN_PATH_SIZE 512

struct storage_summary {
    struct fs_usage fs[3];
    int fs_count;
    unsigned long long total_bytes;
    unsigned long long db_bytes;
    unsigned long long wal_bytes;
    unsigned long long shm_bytes;
    unsigned long long other_bytes;
    unsigned long long largest_bytes;
    int file_count;
    int db_count;
    int wal_count;
    int shm_count;
    char largest_path[DWRT_STORAGE_SCAN_PATH_SIZE];
    char level[16];
    char reason[128];
};

struct storage_backend_status {
    int available;
    char *data_json;
    char health[32];
    char reason[128];
    char error[128];
};

static volatile sig_atomic_t g_stop_requested;
static int g_listen_fd = -1;
static int g_supervisor_mode;
static const char *g_socket_path = DWRT_INIT_SOCKET;
static time_t g_last_rollback_scan_at;
static int g_config_restore_applied_at_boot;
static char g_config_restore_attempted_operation[
    sizeof(((struct dwrt_config_restore_info *)0)->operation_id)];

_Static_assert(sizeof(g_config_restore_attempted_operation) ==
                   sizeof(((struct dwrt_config_restore_info *)0)->operation_id),
               "config restore operation-id buffers must remain the same width");

static int ensure_dir_path(const char *path);
static int ob_appendf(struct outbuf *ob, const char *fmt, ...);
static void ob_append_json_string(struct outbuf *ob, const char *s);

static int path_is_mountpoint(const char *path)
{
    char line[2048];
    char mountpoint[1024];
    FILE *fp;

    if (!path || !path[0])
        return 0;
    fp = fopen("/proc/self/mountinfo", "r");
    if (!fp)
        return 0;
    while (fgets(line, sizeof(line), fp)) {
        mountpoint[0] = '\0';
        if (sscanf(line, "%*s %*s %*s %*s %1023s", mountpoint) == 1 &&
            !strcmp(mountpoint, path)) {
            fclose(fp);
            return 1;
        }
    }
    fclose(fp);
    return 0;
}

static int persistent_store_ready(void)
{
    struct stat st;

    if (access(DWRT_PERSIST_INIT, X_OK) != 0)
        return 1;
    return path_is_mountpoint(DWRT_PERSIST_MOUNT) &&
           stat(DWRT_CONFIG_DB, &st) == 0 && S_ISREG(st.st_mode) &&
           access(DWRT_CONFIG_DB, R_OK | W_OK) == 0;
}

static int wait_for_persistent_store(void)
{
    int waited;

    if (persistent_store_ready())
        return 0;
    fprintf(stderr,
            "dreamingwrt-init: waiting for persistent store mount=%s config=%s\n",
            DWRT_PERSIST_MOUNT, DWRT_CONFIG_DB);
    for (waited = 0; waited < DWRT_PERSIST_WAIT_SECONDS; waited++) {
        if (g_stop_requested)
            return -1;
        sleep(1);
        if (persistent_store_ready()) {
            fprintf(stderr,
                    "dreamingwrt-init: persistent store ready after %ds\n",
                    waited + 1);
            return 0;
        }
    }
    fprintf(stderr,
            "dreamingwrt-init: persistent store unavailable after %ds; refusing to start components\n",
            DWRT_PERSIST_WAIT_SECONDS);
    return -1;
}

static struct component g_components[] = {
    { .name = "dreamingwrt-core", .path = "/usr/bin/dreamingwrt-core", .enabled = 1, .critical = 1, .stop_timeout_sec = 8, .prepare_flags = PREP_CORE },
    { .name = "dreamingwrt-auditd", .path = "/usr/bin/dreamingwrt-auditd", .enabled = 1, .critical = 0, .stop_timeout_sec = 6, .prepare_flags = PREP_AUDIT },
    { .name = "dreamingwrt-rulesd", .path = "/usr/bin/dreamingwrt-rulesd", .enabled = 1, .critical = 0, .stop_timeout_sec = 4, .prepare_flags = PREP_NONE },
    { .name = "dreamingwrt-webd", .path = "/usr/bin/dreamingwrt-webd", .enabled = 1, .critical = 1, .stop_timeout_sec = 6, .prepare_flags = PREP_NONE },
    { .name = "dreamingwrt-logd", .path = "/usr/bin/dreamingwrt-logd", .enabled = 1, .stop_timeout_sec = 4 },
    { .name = "dreamingwrt-notifyd", .path = "/usr/bin/dreamingwrt-notifyd", .enabled = 1, .stop_timeout_sec = 4 },
    { .name = "dreamingwrt-authd", .path = "/usr/bin/dreamingwrt-authd", .enabled = 1, .stop_timeout_sec = 6 },
    { .name = "dreamingwrt-healthd", .path = "/usr/bin/dreamingwrt-healthd", .enabled = 1, .stop_timeout_sec = 4 },
    { .name = "dreamingwrt-metricsd", .path = "/usr/bin/dreamingwrt-metricsd", .enabled = 1, .stop_timeout_sec = 4 },
    { .name = "dreamingwrt-maintenanced", .path = "/usr/bin/dreamingwrt-maintenanced", .enabled = 1, .stop_timeout_sec = 4 },
    { .name = "dreamingwrt-routed", .path = "/usr/bin/dreamingwrt-routed", .enabled = 1, .stop_timeout_sec = 4 },
    { .name = "dreamingwrt-identityd", .path = "/usr/bin/dreamingwrt-identityd", .enabled = 1, .stop_timeout_sec = 4 },
    { .name = "dreamingwrt-flowd", .path = "/usr/bin/dreamingwrt-flowd", .enabled = 1, .stop_timeout_sec = 4 },
    { .name = "dreamingwrt-otad", .path = "/usr/bin/dreamingwrt-otad", .enabled = 1, .stop_timeout_sec = 4 },
    { .name = "dreamingwrt-ac", .path = "/usr/bin/dreamingwrt-ac", .enabled = 0, .critical = 0, .stop_timeout_sec = 6,
      .env_defaults = {
          "DREAMINGWRT_AC_LISTEN_ADDR=0.0.0.0",
          "DREAMINGWRT_AC_LISTEN_PORT=18443",
      } },
    { .name = "dreamingwrt-apd", .path = "/usr/bin/dreamingwrt-apd", .enabled = 0, .critical = 0, .stop_timeout_sec = 6 },
    { .name = "dreamingwrt-aegisxd", .path = "/usr/bin/dreamingwrt-aegisxd", .enabled = 1, .stop_timeout_sec = 4 },
    { .name = "dreamingwrt-honeypotd", .path = "/usr/bin/dreamingwrt-honeypotd", .enabled = 0, .stop_timeout_sec = 4 },
    /*
     * Remote access is opt-in: the component ships disabled and its UCI config
     * is closed by default, so enabling the service alone does not expose the
     * router until a relay host and tunnel token are set.
     */
    { .name = "dreamingos-cloud", .path = "/usr/bin/dreamingos-cloud", .enabled = 0, .critical = 0, .stop_timeout_sec = 6 },
    { .name = "dreamingproxy", .path = "/usr/bin/dreamingproxyd", .alias_name = "dreamingproxyd", .enabled = 0, .stop_timeout_sec = 6 },
};

static void usage(FILE *out)
{
    fprintf(out,
        "Usage:\n"
        "  dreamingwrt-init run\n"
        "  dreamingwrt-init list [--json]\n"
        "  dreamingwrt-init status [component|all] [--json]\n"
        "  dreamingwrt-init check [--json]\n"
        "  dreamingwrt-init enable <component|all>\n"
        "  dreamingwrt-init disable <component|all>\n"
        "  dreamingwrt-init start [component|all]\n"
        "  dreamingwrt-init stop [component|all]\n"
        "  dreamingwrt-init restart [component|all]\n"
        "  dreamingwrt-init rollback-scan [--json]\n"
        "  dreamingwrt-init system-db status [--json]\n"
        "  dreamingwrt-init system-db sync [--json]\n"
        "  dreamingwrt-init config-restore status [--json]\n"
        "  dreamingwrt-init config-restore arm [--json]\n"
        "  dreamingwrt-init config-restore apply --force [--json]\n"
        "  dreamingwrt-init config-restore confirm [--json]\n"
        "  dreamingwrt-init config-restore rollback [--json]\n"
        "\n"
        "Examples:\n"
        "  dreamingwrt-init status\n"
        "  dreamingwrt-init status core\n"
        "  dreamingwrt-init disable rulesd\n"
        "  dreamingwrt-init enable webd\n"
        "  dreamingwrt-init restart core\n"
        "  dreamingwrt-init restart webd\n"
        "  dreamingwrt-init status honeypotd\n"
        "  dreamingwrt-init restart dreamingwrt-core\n"
        "  dreamingwrt-init stop dreamingwrt-webd\n"
        "  dreamingwrt-init rollback-scan --json\n"
        "  dreamingwrt-init system-db status --json\n"
        "  dreamingwrt-init config-restore status --json\n"
        "\n"
        "Options:\n"
        "  -h, --help       Show this help\n"
        "  --json           Emit JSON for list/status/check\n"
        "  --socket <path>  Override control socket; default: " DWRT_INIT_SOCKET "\n");
}

static int emit_system_db_status(struct outbuf *out, int apply, int json,
                                 int *conflicts_out)
{
    struct dwrt_system_db_status status;
    size_t i;
    int rc;

    rc = apply ? dwrt_system_db_sync(&status) : dwrt_system_db_inspect(&status);
    if (conflicts_out)
        *conflicts_out = status.conflicts;
    if (json) {
        ob_appendf(out,
                   "{\"ok\":%s,\"applied\":%s,\"changed\":%d,\"errors\":%d,\"conflicts\":%d,\"components_restart_allowed\":%s,\"databases\":[",
                   rc == 0 ? "true" : "false", apply ? "true" : "false",
                   status.changed, status.errors, status.conflicts,
                   status.conflicts ? "false" : "true");
        for (i = 0; i < status.count; i++) {
            const struct dwrt_system_db_item_status *item = &status.items[i];
            if (i)
                ob_appendf(out, ",");
            ob_appendf(out, "{\"name\":");
            ob_append_json_string(out, item->name);
            ob_appendf(out, ",\"source\":");
            ob_append_json_string(out, item->source);
            ob_appendf(out, ",\"target\":");
            ob_append_json_string(out, item->target);
            ob_appendf(out, ",\"source_selection\":");
            ob_append_json_string(out, item->source_selection);
            ob_appendf(out, ",\"source_sha256\":");
            ob_append_json_string(out, item->source_sha256);
            ob_appendf(out, ",\"target_sha256\":");
            ob_append_json_string(out, item->target_sha256);
            ob_appendf(out, ",\"firmware_identity\":");
            ob_append_json_string(out, item->firmware_identity);
            ob_appendf(out, ",\"applied_firmware_identity\":");
            ob_append_json_string(out, item->applied_firmware_identity);
            ob_appendf(out, ",\"applied_source_sha256\":");
            ob_append_json_string(out, item->applied_source_sha256);
            ob_appendf(out,
                       ",\"source_valid\":%s,\"source_conflict\":%s,\"target_valid\":%s,\"changed\":%s,\"action\":",
                       item->source_valid ? "true" : "false",
                       item->source_conflict ? "true" : "false",
                       item->target_valid ? "true" : "false",
                       item->changed ? "true" : "false");
            ob_append_json_string(out, item->action);
            ob_appendf(out, ",\"error\":");
            ob_append_json_string(out, item->error);
            ob_appendf(out, "}");
        }
        ob_appendf(out, "]}\n");
    } else {
        ob_appendf(out, "system databases: action=%s changed=%d errors=%d conflicts=%d\n",
                   apply ? "sync" : "status", status.changed, status.errors,
                   status.conflicts);
        for (i = 0; i < status.count; i++) {
            const struct dwrt_system_db_item_status *item = &status.items[i];
            ob_appendf(out,
                       "%-12s source=%s selection=%s source_valid=%s conflict=%s target_valid=%s changed=%s action=%s source_sha256=%s target_sha256=%s%s%s\n",
                       item->name, item->source[0] ? item->source : "-",
                       item->source_selection[0] ? item->source_selection : "none",
                       item->source_valid ? "yes" : "no",
                       item->source_conflict ? "yes" : "no",
                       item->target_valid ? "yes" : "no",
                       item->changed ? "yes" : "no", item->action,
                       item->source_sha256[0] ? item->source_sha256 : "-",
                       item->target_sha256[0] ? item->target_sha256 : "-",
                       item->error[0] ? " error=" : "", item->error);
        }
    }
    return rc == 0 ? 0 : 1;
}

static void ob_init(struct outbuf *ob)
{
    memset(ob, 0, sizeof(*ob));
}

static void ob_free(struct outbuf *ob)
{
    free(ob->data);
    memset(ob, 0, sizeof(*ob));
}

static int ob_reserve(struct outbuf *ob, size_t need)
{
    char *p;
    size_t ncap = ob->cap ? ob->cap : 512;

    while (ncap < need)
        ncap *= 2;
    if (ncap == ob->cap)
        return 0;
    p = realloc(ob->data, ncap);
    if (!p)
        return -1;
    ob->data = p;
    ob->cap = ncap;
    return 0;
}

static int ob_appendf(struct outbuf *ob, const char *fmt, ...)
{
    va_list ap;
    int n;

    for (;;) {
        if (ob_reserve(ob, ob->len + 256) != 0)
            return -1;
        va_start(ap, fmt);
        n = vsnprintf(ob->data + ob->len, ob->cap - ob->len, fmt, ap);
        va_end(ap);
        if (n < 0)
            return -1;
        if (ob->len + (size_t)n < ob->cap) {
            ob->len += (size_t)n;
            return 0;
        }
        if (ob_reserve(ob, ob->len + (size_t)n + 1) != 0)
            return -1;
    }
}

static int ob_append_mem(struct outbuf *ob, const char *data, size_t len)
{
    if (!data || !len)
        return 0;
    if (ob_reserve(ob, ob->len + len + 1) != 0)
        return -1;
    memcpy(ob->data + ob->len, data, len);
    ob->len += len;
    ob->data[ob->len] = '\0';
    return 0;
}

static void ob_append_json_string(struct outbuf *ob, const char *s)
{
    const unsigned char *p = (const unsigned char *)(s ? s : "");

    ob_appendf(ob, "\"");
    for (; *p; p++) {
        switch (*p) {
        case '\\':
            ob_appendf(ob, "\\\\");
            break;
        case '"':
            ob_appendf(ob, "\\\"");
            break;
        case '\b':
            ob_appendf(ob, "\\b");
            break;
        case '\f':
            ob_appendf(ob, "\\f");
            break;
        case '\n':
            ob_appendf(ob, "\\n");
            break;
        case '\r':
            ob_appendf(ob, "\\r");
            break;
        case '\t':
            ob_appendf(ob, "\\t");
            break;
        default:
            if (*p < 0x20)
                ob_appendf(ob, "\\u%04x", *p);
            else
                ob_appendf(ob, "%c", *p);
            break;
        }
    }
    ob_appendf(ob, "\"");
}

static const char *base_name(const char *path)
{
    const char *p;
    if (!path)
        return "";
    p = strrchr(path, '/');
    return p ? p + 1 : path;
}

static const char *short_name(const struct component *c)
{
    static const char prefix[] = "dreamingwrt-";

    if (!c || !c->name)
        return "";
    if (strncmp(c->name, prefix, strlen(prefix)) == 0)
        return c->name + strlen(prefix);
    return c->name;
}

static int component_name_matches(const struct component *c, const char *name)
{
    if (!c || !name || !name[0])
        return 0;
    if (strcmp(name, c->name) == 0)
        return 1;
    if (strcmp(name, short_name(c)) == 0)
        return 1;
    if (c->alias_name && strcmp(name, c->alias_name) == 0)
        return 1;
    if (strcmp(name, base_name(c->path)) == 0)
        return 1;
    if (c->alias_path && strcmp(name, base_name(c->alias_path)) == 0)
        return 1;
    return 0;
}

static int file_exists_exec(const char *path)
{
    return path && access(path, X_OK) == 0;
}

static const char *select_exec_path(const struct component *c)
{
    if (file_exists_exec(c->path))
        return c->path;
    if (file_exists_exec(c->alias_path))
        return c->alias_path;
    return NULL;
}

static int is_pid_dir(const char *s)
{
    const unsigned char *p = (const unsigned char *)s;
    if (!s || !s[0])
        return 0;
    for (; *p; p++) {
        if (!isdigit(*p))
            return 0;
    }
    return 1;
}

static int read_file(const char *path, char *buf, size_t buflen)
{
    int fd;
    ssize_t n;

    if (!buflen)
        return -1;
    fd = open(path, O_RDONLY);
    if (fd < 0)
        return -1;
    n = read(fd, buf, buflen - 1);
    close(fd);
    if (n < 0)
        return -1;
    buf[n] = '\0';
    return (int)n;
}

static void set_fd_cloexec(int fd)
{
    int flags;

    if (fd < 0)
        return;
    flags = fcntl(fd, F_GETFD);
    if (flags < 0)
        return;
    fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
}

static void close_exec_extra_fds(void)
{
    long max_fd = sysconf(_SC_OPEN_MAX);
    int fd;

    if (max_fd < 0 || max_fd > 4096)
        max_fd = 4096;
    for (fd = 3; fd < max_fd; fd++)
        close(fd);
}

static char *read_command_output(const char *cmd, size_t max_len)
{
    FILE *fp;
    char *buf = NULL;
    size_t len = 0;
    size_t cap = 0;
    char tmp[1024];

    if (!cmd || !max_len)
        return NULL;
    fp = popen(cmd, "r");
    if (!fp)
        return NULL;
    while (len < max_len && fgets(tmp, sizeof(tmp), fp)) {
        size_t n = strlen(tmp);
        char *p;

        if (len + n + 1 > max_len) {
            n = max_len > len ? max_len - len : 0;
        }
        if (len + n + 1 > cap) {
            size_t ncap = cap ? cap * 2 : 4096;
            while (ncap < len + n + 1)
                ncap *= 2;
            p = realloc(buf, ncap);
            if (!p) {
                free(buf);
                pclose(fp);
                return NULL;
            }
            buf = p;
            cap = ncap;
        }
        if (n) {
            memcpy(buf + len, tmp, n);
            len += n;
        }
        if (!n)
            break;
    }
    if (pclose(fp) != 0) {
        free(buf);
        return NULL;
    }
    if (!buf) {
        buf = calloc(1, 1);
        return buf;
    }
    buf[len] = '\0';
    return buf;
}

static char *json_extract_object_field(const char *json, const char *field)
{
    char pattern[96];
    const char *p;
    const char *start;
    int depth = 0;
    int in_str = 0;
    int esc = 0;

    if (!json || !field || strlen(field) > 64)
        return NULL;
    snprintf(pattern, sizeof(pattern), "\"%s\"", field);
    p = strstr(json, pattern);
    if (!p)
        return NULL;
    p += strlen(pattern);
    while (*p && isspace((unsigned char)*p))
        p++;
    if (*p != ':')
        return NULL;
    p++;
    while (*p && isspace((unsigned char)*p))
        p++;
    if (*p != '{')
        return NULL;
    start = p;
    for (; *p; p++) {
        if (esc) {
            esc = 0;
            continue;
        }
        if (*p == '\\' && in_str) {
            esc = 1;
            continue;
        }
        if (*p == '"') {
            in_str = !in_str;
            continue;
        }
        if (in_str)
            continue;
        if (*p == '{')
            depth++;
        else if (*p == '}') {
            depth--;
            if (depth == 0) {
                size_t len = (size_t)(p - start + 1);
                char *out = malloc(len + 1);
                if (!out)
                    return NULL;
                memcpy(out, start, len);
                out[len] = '\0';
                return out;
            }
        }
    }
    return NULL;
}

static int json_extract_bool_field(const char *json, const char *field,
                                   int *value)
{
    char pattern[96];
    const char *p;

    if (!json || !field || !value || strlen(field) > 64)
        return -1;
    snprintf(pattern, sizeof(pattern), "\"%s\"", field);
    p = strstr(json, pattern);
    if (!p)
        return -1;
    p += strlen(pattern);
    while (*p && isspace((unsigned char)*p))
        p++;
    if (*p != ':')
        return -1;
    p++;
    while (*p && isspace((unsigned char)*p))
        p++;
    if (!strncmp(p, "true", 4)) {
        *value = 1;
        return 0;
    }
    if (!strncmp(p, "false", 5)) {
        *value = 0;
        return 0;
    }
    if (*p == '1' || *p == '0') {
        *value = *p == '1';
        return 0;
    }
    return -1;
}

static int json_extract_string_field(const char *json, const char *field,
                                     char *out, size_t out_len)
{
    char pattern[96];
    const char *p;
    size_t used = 0;
    int esc = 0;

    if (!json || !field || !out || !out_len || strlen(field) > 64)
        return -1;
    out[0] = '\0';
    snprintf(pattern, sizeof(pattern), "\"%s\"", field);
    p = strstr(json, pattern);
    if (!p)
        return -1;
    p += strlen(pattern);
    while (*p && isspace((unsigned char)*p))
        p++;
    if (*p != ':')
        return -1;
    p++;
    while (*p && isspace((unsigned char)*p))
        p++;
    if (*p != '"')
        return -1;
    p++;
    for (; *p; p++) {
        char ch = *p;

        if (esc) {
            switch (ch) {
            case 'n': ch = '\n'; break;
            case 'r': ch = '\r'; break;
            case 't': ch = '\t'; break;
            case 'b': ch = '\b'; break;
            case 'f': ch = '\f'; break;
            default: break;
            }
            esc = 0;
        } else if (ch == '\\') {
            esc = 1;
            continue;
        } else if (ch == '"') {
            out[used] = '\0';
            return 0;
        }
        if (used + 1 < out_len)
            out[used++] = ch;
    }
    out[used] = '\0';
    return -1;
}

static int ensure_dir_path(const char *path)
{
    char tmp[256];
    char *p;

    if (!path || !path[0])
        return -1;
    snprintf(tmp, sizeof(tmp), "%s", path);
    for (p = tmp + 1; *p; p++) {
        if (*p != '/')
            continue;
        *p = '\0';
        if (mkdir(tmp, 0755) != 0 && errno != EEXIST)
            return -1;
        *p = '/';
    }
    return 0;
}

static void load_config(void)
{
    char *raw;
    char *components = NULL;
    size_t i;

    raw = read_command_output("cat " DWRT_INIT_CONFIG " 2>/dev/null", 64 * 1024);
    if (!raw)
        return;
    components = json_extract_object_field(raw, "components");
    if (!components) {
        free(raw);
        return;
    }
    for (i = 0; i < ARRAY_SIZE(g_components); i++) {
        char *co = json_extract_object_field(components, g_components[i].name);
        int enabled;

        if (!co)
            continue;
        if (json_extract_bool_field(co, "enabled", &enabled) == 0) {
            g_components[i].enabled = enabled ? 1 : 0;
            if (!g_components[i].enabled)
                g_components[i].desired = 0;
        }
        free(co);
    }
    free(components);
    free(raw);
}

static int save_config(void)
{
    char tmp_path[320];
    FILE *fp;
    size_t i;

    if (ensure_dir_path(DWRT_INIT_CONFIG) != 0)
        return -1;
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp.%ld", DWRT_INIT_CONFIG, (long)getpid());
    fp = fopen(tmp_path, "w");
    if (!fp)
        return -1;
    fprintf(fp, "{\n  \"version\": 1,\n  \"components\": {\n");
    for (i = 0; i < ARRAY_SIZE(g_components); i++) {
        fprintf(fp, "    \"%s\": {\"enabled\": %s}%s\n",
                g_components[i].name,
                g_components[i].enabled ? "true" : "false",
                i + 1 < ARRAY_SIZE(g_components) ? "," : "");
    }
    fprintf(fp, "  }\n}\n");
    if (fclose(fp) != 0) {
        unlink(tmp_path);
        return -1;
    }
    if (rename(tmp_path, DWRT_INIT_CONFIG) != 0) {
        unlink(tmp_path);
        return -1;
    }
    chmod(DWRT_INIT_CONFIG, 0644);
    return 0;
}

static void storage_backend_status_free(struct storage_backend_status *bs)
{
    if (!bs)
        return;
    free(bs->data_json);
    memset(bs, 0, sizeof(*bs));
}

static int storage_backend_status_collect(struct storage_backend_status *bs)
{
    char *raw;
    char *data;

    if (!bs)
        return -1;
    memset(bs, 0, sizeof(*bs));
    raw = read_command_output(
        "ubus -t 2 call dreamingwrt storage_status '{\"tables\":true}' 2>/dev/null",
        256 * 1024);
    if (!raw) {
        snprintf(bs->error, sizeof(bs->error), "ubus_storage_status_unavailable");
        return -1;
    }
    data = json_extract_object_field(raw, "data");
    if (!data) {
        snprintf(bs->error, sizeof(bs->error), "ubus_storage_status_invalid");
        free(raw);
        return -1;
    }
    bs->available = 1;
    bs->data_json = data;
    if (json_extract_string_field(data, "health", bs->health, sizeof(bs->health)) != 0)
        json_extract_string_field(data, "level", bs->health, sizeof(bs->health));
    if (json_extract_string_field(data, "reason", bs->reason, sizeof(bs->reason)) != 0)
        snprintf(bs->reason, sizeof(bs->reason), "storage_status_from_core");
    free(raw);
    return 0;
}

static long system_uptime_sec(void)
{
    char buf[64];
    double up = 0.0;

    if (read_file("/proc/uptime", buf, sizeof(buf)) <= 0)
        return 0;
    if (sscanf(buf, "%lf", &up) != 1 || up < 0.0)
        return 0;
    return (long)up;
}

static long pid_uptime_sec(pid_t pid)
{
    char path[64];
    char buf[2048];
    char *rp;
    char *p;
    long uptime;
    unsigned long long start_ticks = 0;
    long ticks;
    int field = 3;

    if (pid <= 1)
        return 0;
    snprintf(path, sizeof(path), "/proc/%ld/stat", (long)pid);
    if (read_file(path, buf, sizeof(buf)) <= 0)
        return 0;
    rp = strrchr(buf, ')');
    if (!rp)
        return 0;
    p = rp + 2;
    while (*p && field <= 22) {
        char *end = p;
        while (*end && *end != ' ' && *end != '\n')
            end++;
        if (field == 22) {
            start_ticks = strtoull(p, NULL, 10);
            break;
        }
        p = end;
        while (*p == ' ')
            p++;
        field++;
    }
    if (!start_ticks)
        return 0;
    ticks = sysconf(_SC_CLK_TCK);
    if (ticks <= 0)
        ticks = 100;
    uptime = system_uptime_sec() - (long)(start_ticks / (unsigned long long)ticks);
    return uptime > 0 ? uptime : 0;
}

static int has_suffix(const char *s, const char *suffix)
{
    size_t slen;
    size_t xlen;

    if (!s || !suffix)
        return 0;
    slen = strlen(s);
    xlen = strlen(suffix);
    return slen >= xlen && strcmp(s + slen - xlen, suffix) == 0;
}

static void storage_add_file(struct storage_summary *st, const char *path,
                             unsigned long long bytes)
{
    st->file_count++;
    st->total_bytes += bytes;
    if (bytes > st->largest_bytes) {
        st->largest_bytes = bytes;
        snprintf(st->largest_path, sizeof(st->largest_path), "%s", path ? path : "");
    }
    if (has_suffix(path, ".db")) {
        st->db_count++;
        st->db_bytes += bytes;
    } else if (has_suffix(path, "-wal")) {
        st->wal_count++;
        st->wal_bytes += bytes;
    } else if (has_suffix(path, "-shm")) {
        st->shm_count++;
        st->shm_bytes += bytes;
    } else {
        st->other_bytes += bytes;
    }
}

static void storage_scan_dir(struct storage_summary *st, const char *dir_path)
{
    DIR *d;
    struct dirent *de;

    d = opendir(dir_path);
    if (!d)
        return;
    while ((de = readdir(d)) != NULL) {
        char path[DWRT_STORAGE_SCAN_PATH_SIZE];
        struct stat sb;

        if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
            continue;
        if (snprintf(path, sizeof(path), "%s/%s", dir_path, de->d_name) >= (int)sizeof(path))
            continue;
        if (lstat(path, &sb) != 0)
            continue;
        if (S_ISDIR(sb.st_mode)) {
            storage_scan_dir(st, path);
        } else if (S_ISREG(sb.st_mode)) {
            storage_add_file(st, path, (unsigned long long)sb.st_size);
        }
    }
    closedir(d);
}

static void storage_fill_fs(struct fs_usage *fs, const char *name, const char *path)
{
    struct statvfs vfs;
    unsigned long long total;
    unsigned long long avail;
    unsigned long long used;

    memset(fs, 0, sizeof(*fs));
    fs->name = name;
    fs->path = path;
    if (statvfs(path, &vfs) != 0)
        return;
    total = (unsigned long long)vfs.f_blocks * (unsigned long long)vfs.f_frsize;
    avail = (unsigned long long)vfs.f_bavail * (unsigned long long)vfs.f_frsize;
    used = total > avail ? total - avail : 0;
    fs->total_bytes = total;
    fs->avail_bytes = avail;
    fs->used_bytes = used;
    fs->used_pct = total ? (int)((used * 100ULL) / total) : 0;
    fs->ok = 1;
}

static void storage_summary_collect(struct storage_summary *st)
{
    int i;

    memset(st, 0, sizeof(*st));
    snprintf(st->level, sizeof(st->level), "ok");
    st->fs_count = 3;
    storage_fill_fs(&st->fs[0], "root", "/");
    storage_fill_fs(&st->fs[1], "tmp", "/tmp");
    storage_fill_fs(&st->fs[2], "opt", "/opt");
    storage_scan_dir(st, "/etc/dreamingwrt");
    storage_scan_dir(st, "/opt/dreamingwrt/audit");

    for (i = 0; i < st->fs_count; i++) {
        if (!st->fs[i].ok)
            continue;
        if (st->fs[i].used_pct >= DWRT_CRIT_FS_PCT) {
            snprintf(st->level, sizeof(st->level), "critical");
            snprintf(st->reason, sizeof(st->reason), "%s filesystem %d%% used",
                     st->fs[i].name, st->fs[i].used_pct);
            return;
        }
        if (!strcmp(st->level, "ok") && st->fs[i].used_pct >= DWRT_WARN_FS_PCT) {
            snprintf(st->level, sizeof(st->level), "warning");
            snprintf(st->reason, sizeof(st->reason), "%s filesystem %d%% used",
                     st->fs[i].name, st->fs[i].used_pct);
        }
    }
    if (st->largest_bytes >= DWRT_CRIT_DB_BYTES || st->wal_bytes >= DWRT_CRIT_WAL_BYTES) {
        snprintf(st->level, sizeof(st->level), "critical");
        snprintf(st->reason, sizeof(st->reason), "database storage is above critical watermark");
    } else if (!strcmp(st->level, "ok") &&
               (st->largest_bytes >= DWRT_WARN_DB_BYTES || st->wal_bytes >= DWRT_WARN_WAL_BYTES)) {
        snprintf(st->level, sizeof(st->level), "warning");
        snprintf(st->reason, sizeof(st->reason), "database storage is above warning watermark");
    }
    if (!st->reason[0])
        snprintf(st->reason, sizeof(st->reason), "storage within watermarks");
}

static int token_matches_component(const char *tok, const struct component *c)
{
    const char *b = base_name(tok);
    if (!tok || !tok[0])
        return 0;
    if (c->path && strcmp(tok, c->path) == 0)
        return 1;
    if (c->alias_path && strcmp(tok, c->alias_path) == 0)
        return 1;
    if (c->name && strcmp(b, c->name) == 0)
        return 1;
    if (c->alias_name && strcmp(b, c->alias_name) == 0)
        return 1;
    if (c->path && strcmp(b, base_name(c->path)) == 0)
        return 1;
    if (c->alias_path && strcmp(b, base_name(c->alias_path)) == 0)
        return 1;
    return 0;
}

/*
 * True when the pid is running the dreamingwrt-init binary itself, whether as
 * the supervisor or as a short-lived CLI invocation. Identity comes from
 * argv[0] plus /proc/<pid>/comm; the CLI's own arguments are deliberately not
 * consulted because those name the component being acted on, not the program.
 */
static int pid_is_init_tool(pid_t pid)
{
    char path[64];
    char buf[4096];
    const char *self = base_name(DWRT_INIT_SELF_PATH);
    int n;

    snprintf(path, sizeof(path), "/proc/%ld/cmdline", (long)pid);
    n = read_file(path, buf, sizeof(buf));
    if (n > 0 && buf[0] && strcmp(base_name(buf), self) == 0)
        return 1;

    snprintf(path, sizeof(path), "/proc/%ld/comm", (long)pid);
    n = read_file(path, buf, sizeof(buf));
    if (n > 0) {
        size_t len;
        char *nl = strchr(buf, '\n');
        if (nl)
            *nl = '\0';
        len = strlen(buf);
        /*
         * comm is capped at 15 characters by the kernel, so "dreamingwrt-init"
         * (16 chars) arrives truncated as "dreamingwrt-ini". Accept that form
         * as well, but only at the full 15-character cap so shorter names
         * cannot match by prefix.
         */
        if (len && strcmp(buf, self) == 0)
            return 1;
        if (len == 15 && strncmp(self, buf, len) == 0)
            return 1;
    }
    return 0;
}

static int pid_matches_component(pid_t pid, const struct component *c)
{
    char path[64];
    char buf[4096];
    int n;
    int pos = 0;

    if (pid <= 1 || pid == getpid())
        return 0;
    /*
     * dreamingwrt-init is never a component, and its own argv carries the
     * component name it was asked to act on ("dreamingwrt-init restart
     * dreamingwrt-webd"). Without this guard the token scan below matches the
     * very CLI that requested the restart and the supervisor SIGTERMs it as a
     * stray orphan, so the caller sees "Terminated" even though the restart
     * itself succeeded. Interpreter-launched components such as rulesd keep
     * their name in argv[1], so the token scan has to stay.
     */
    if (pid_is_init_tool(pid))
        return 0;

    snprintf(path, sizeof(path), "/proc/%ld/cmdline", (long)pid);
    n = read_file(path, buf, sizeof(buf));
    if (n > 0) {
        while (pos < n) {
            const char *tok = buf + pos;
            size_t len = strlen(tok);
            if (token_matches_component(tok, c))
                return 1;
            pos += (int)len + 1;
        }
    }

    snprintf(path, sizeof(path), "/proc/%ld/comm", (long)pid);
    n = read_file(path, buf, sizeof(buf));
    if (n > 0) {
        char *nl = strchr(buf, '\n');
        if (nl)
            *nl = '\0';
        if (c->name && strcmp(buf, c->name) == 0)
            return 1;
        if (c->alias_name && strcmp(buf, c->alias_name) == 0)
            return 1;
        if (c->path && strcmp(buf, base_name(c->path)) == 0)
            return 1;
        if (c->alias_path && strcmp(buf, base_name(c->alias_path)) == 0)
            return 1;
    }
    return 0;
}

static int pid_parent_is(pid_t pid, pid_t parent)
{
    char path[64];
    char buf[1024];
    char *line;
    int n;

    if (pid <= 1 || parent <= 1)
        return 0;
    snprintf(path, sizeof(path), "/proc/%ld/status", (long)pid);
    n = read_file(path, buf, sizeof(buf));
    if (n <= 0)
        return 0;
    buf[n < (int)sizeof(buf) ? n : (int)sizeof(buf) - 1] = '\0';
    line = strstr(buf, "\nPPid:");
    if (!line && !strncmp(buf, "PPid:", 5))
        line = buf;
    if (!line)
        return 0;
    line = strchr(line, ':');
    if (!line)
        return 0;
    while (*++line && isspace((unsigned char)*line))
        ;
    return (pid_t)strtol(line, NULL, 10) == parent;
}

static pid_t find_component_pid(const struct component *c)
{
    DIR *d;
    struct dirent *de;
    pid_t found = 0;

    d = opendir("/proc");
    if (!d)
        return 0;
    while ((de = readdir(d)) != NULL) {
        pid_t pid;
        if (!is_pid_dir(de->d_name))
            continue;
        pid = (pid_t)strtol(de->d_name, NULL, 10);
        if (pid_matches_component(pid, c)) {
            found = pid;
            break;
        }
    }
    closedir(d);
    return found;
}

static long component_uptime_sec(const struct component *c, time_t now)
{
    if (!c || c->pid <= 0 || c->started_at <= 0 || now < c->started_at)
        return 0;
    return (long)(now - c->started_at);
}

static long component_reported_uptime_sec(const struct component *c, pid_t pid, int supervised, time_t now)
{
    long up;

    if (supervised) {
        up = component_uptime_sec(c, now);
        if (up > 0)
            return up;
    }
    return pid_uptime_sec(pid);
}

static int decode_exit_code(int status)
{
    if (WIFEXITED(status))
        return WEXITSTATUS(status);
    return -1;
}

static int decode_exit_signal(int status)
{
    if (WIFSIGNALED(status))
        return WTERMSIG(status);
    return 0;
}

static int next_backoff_sec(struct component *c, time_t now)
{
    long runtime = component_uptime_sec(c, now);
    int next;

    if (runtime >= 60)
        c->crash_count = 0;
    else
        c->crash_count++;

    if (c->crash_count <= 1)
        next = 2;
    else {
        next = c->backoff_sec > 0 ? c->backoff_sec * 2 : 4;
        if (next < 2)
            next = 2;
    }
    if (next > DWRT_MAX_RESPAWN_BACKOFF_SEC)
        next = DWRT_MAX_RESPAWN_BACKOFF_SEC;
    c->backoff_sec = next;
    return next;
}

static long component_respawn_in_sec(struct component *c, time_t now)
{
    long remaining;
    int delay;

    if (!c || c->next_respawn_at <= 0)
        return 0;
    if (c->next_respawn_at <= now) {
        c->next_respawn_at = 0;
        return 0;
    }
    remaining = (long)(c->next_respawn_at - now);
    if (remaining <= DWRT_MAX_RESPAWN_BACKOFF_SEC)
        return remaining;

    /* Wall clock may move backwards when NTP first synchronizes after boot.
     * Re-anchor impossible deadlines so a 60-second crash backoff cannot turn
     * into hours of downtime. */
    delay = c->backoff_sec;
    if (delay <= 0 || delay > DWRT_MAX_RESPAWN_BACKOFF_SEC)
        delay = DWRT_MAX_RESPAWN_BACKOFF_SEC;
    c->next_respawn_at = now + delay;
    return delay;
}

static int count_component_pids(const struct component *c)
{
    DIR *d;
    struct dirent *de;
    int count = 0;

    d = opendir("/proc");
    if (!d)
        return 0;
    while ((de = readdir(d)) != NULL) {
        pid_t pid;
        if (!is_pid_dir(de->d_name))
            continue;
        pid = (pid_t)strtol(de->d_name, NULL, 10);
        if (pid_matches_component(pid, c))
            count++;
    }
    closedir(d);
    return count;
}

static int signal_component_pids(const struct component *c, int sig)
{
    DIR *d;
    struct dirent *de;
    int count = 0;

    d = opendir("/proc");
    if (!d)
        return 0;
    while ((de = readdir(d)) != NULL) {
        pid_t pid;
        if (!is_pid_dir(de->d_name))
            continue;
        pid = (pid_t)strtol(de->d_name, NULL, 10);
        if (!pid_matches_component(pid, c))
            continue;
        if (kill(pid, sig) == 0)
            count++;
    }
    closedir(d);
    return count;
}

static int signal_component_orphan_pids(const struct component *c, pid_t keep_pid, int sig)
{
    DIR *d;
    struct dirent *de;
    int count = 0;

    d = opendir("/proc");
    if (!d)
        return 0;
    while ((de = readdir(d)) != NULL) {
        pid_t pid;
        if (!is_pid_dir(de->d_name))
            continue;
        pid = (pid_t)strtol(de->d_name, NULL, 10);
        if (pid <= 1 || pid == getpid() || (keep_pid > 0 && (pid == keep_pid || pid_parent_is(pid, keep_pid))))
            continue;
        if (!pid_matches_component(pid, c))
            continue;
        if (kill(pid, sig) == 0)
            count++;
    }
    closedir(d);
    return count;
}

static int count_component_orphan_pids(const struct component *c, pid_t keep_pid)
{
    DIR *d;
    struct dirent *de;
    int count = 0;

    d = opendir("/proc");
    if (!d)
        return 0;
    while ((de = readdir(d)) != NULL) {
        pid_t pid;
        if (!is_pid_dir(de->d_name))
            continue;
        pid = (pid_t)strtol(de->d_name, NULL, 10);
        if (pid <= 1 || pid == getpid() || (keep_pid > 0 && (pid == keep_pid || pid_parent_is(pid, keep_pid))))
            continue;
        if (pid_matches_component(pid, c))
            count++;
    }
    closedir(d);
    return count;
}

static int cleanup_component_orphans(struct component *c, pid_t keep_pid,
                                     struct outbuf *out, int quiet)
{
    int waited = 0;
    int timeout;
    int count;

    if (!c)
        return 0;
    count = count_component_orphan_pids(c, keep_pid);
    if (count <= 0)
        return 0;
    if (!quiet)
        ob_appendf(out, "%s cleaning %d orphan process(es) keep_pid=%ld\n",
                   c->name, count, (long)keep_pid);
    signal_component_orphan_pids(c, keep_pid, SIGTERM);
    timeout = c->stop_timeout_sec > 0 ? c->stop_timeout_sec : 4;
    while (waited < timeout) {
        if (count_component_orphan_pids(c, keep_pid) <= 0)
            return count;
        sleep(1);
        waited++;
    }
    signal_component_orphan_pids(c, keep_pid, SIGKILL);
    sleep(1);
    return count;
}

static struct component *find_component(const char *name)
{
    size_t i;
    if (!name || !name[0])
        return NULL;
    for (i = 0; i < ARRAY_SIZE(g_components); i++) {
        struct component *c = &g_components[i];
        if (component_name_matches(c, name))
            return c;
    }
    return NULL;
}

static void sig_handler(int sig)
{
    (void)sig;
    g_stop_requested = 1;
}

static int run_shell_quiet(const char *cmd)
{
    int rc = system(cmd);
    if (rc == -1)
        return -1;
    if (WIFEXITED(rc))
        return WEXITSTATUS(rc);
    return -1;
}

static int copy_file_simple(const char *src, const char *dst, char *err, size_t err_len)
{
    int in = -1;
    int out = -1;
    char buf[8192];
    ssize_t n;
    int rc = -1;

    if (err && err_len)
        err[0] = '\0';
    if (!src || !dst || src[0] != '/' || dst[0] != '/') {
        if (err && err_len)
            snprintf(err, err_len, "invalid_path");
        return -1;
    }
    in = open(src, O_RDONLY);
    if (in < 0) {
        if (err && err_len)
            snprintf(err, err_len, "open_src_failed:%s", strerror(errno));
        goto out;
    }
    out = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (out < 0) {
        if (err && err_len)
            snprintf(err, err_len, "open_dst_failed:%s", strerror(errno));
        goto out;
    }
    while ((n = read(in, buf, sizeof(buf))) > 0) {
        char *p = buf;
        ssize_t left = n;

        while (left > 0) {
            ssize_t w = write(out, p, (size_t)left);

            if (w < 0) {
                if (err && err_len)
                    snprintf(err, err_len, "write_failed:%s", strerror(errno));
                goto out;
            }
            p += w;
            left -= w;
        }
    }
    if (n < 0) {
        if (err && err_len)
            snprintf(err, err_len, "read_failed:%s", strerror(errno));
        goto out;
    }
    if (fsync(out) != 0) {
        if (err && err_len)
            snprintf(err, err_len, "fsync_failed:%s", strerror(errno));
        goto out;
    }
    rc = 0;
out:
    if (out >= 0)
        close(out);
    if (in >= 0)
        close(in);
    return rc;
}

static int snapshot_path_safe(const char *path)
{
    const char prefix[] = DWRT_NETWORK_BACKUP_DIR "/";

    if (!path || !path[0] || path[0] != '/')
        return 0;
    if (strncmp(path, prefix, sizeof(prefix) - 1) != 0)
        return 0;
    if (strstr(path, "/../") || strstr(path, "/..") || strstr(path, "../"))
        return 0;
    return access(path, R_OK) == 0;
}

static int restore_network_snapshot(const char *snapshot_path, char *err, size_t err_len)
{
    char pre_path[320];
    char copy_err[160] = "";
    time_t now = time(NULL);

    if (err && err_len)
        err[0] = '\0';
    if (!snapshot_path || !snapshot_path[0]) {
        if (err && err_len)
            snprintf(err, err_len, "snapshot_path_missing");
        return -1;
    }
    if (!snapshot_path_safe(snapshot_path)) {
        if (err && err_len)
            snprintf(err, err_len, "snapshot_not_readable_or_outside_backup_dir");
        return -1;
    }
    if (ensure_dir_path(DWRT_NETWORK_BACKUP_DIR "/") != 0) {
        if (err && err_len)
            snprintf(err, err_len, "backup_dir_failed:%s", strerror(errno));
        return -1;
    }
    snprintf(pre_path, sizeof(pre_path), "%s/network.pre-auto-rollback.%ld.%ld.bak",
             DWRT_NETWORK_BACKUP_DIR, (long)now, (long)getpid());
    (void)copy_file_simple(DWRT_NETWORK_CONFIG, pre_path, copy_err, sizeof(copy_err));
    if (copy_file_simple(snapshot_path, DWRT_NETWORK_CONFIG, err, err_len) != 0)
        return -1;
    sync();
    return 0;
}

struct rollback_scan_result {
    int available;
    int scanned;
    int expired;
    int rolled_back;
    int failed;
    int skipped;
    char error[160];
};

static int config_apply_table_exists(sqlite3 *db)
{
    sqlite3_stmt *st = NULL;
    int exists = 0;

    if (!db)
        return 0;
    if (sqlite3_prepare_v2(db,
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='config_apply_tasks'",
            -1, &st, NULL) != SQLITE_OK)
        return 0;
    if (sqlite3_step(st) == SQLITE_ROW)
        exists = 1;
    sqlite3_finalize(st);
    return exists;
}

static int auto_rollback_one(sqlite3 *db, int id, const char *snapshot,
                             struct rollback_scan_result *r)
{
    sqlite3_stmt *st = NULL;
    char err[160] = "";
    int restored = 0;
    int64_t now = (int64_t)time(NULL);

    if (!db || !r)
        return -1;
    if (snapshot && snapshot[0])
        restored = (restore_network_snapshot(snapshot, err, sizeof(err)) == 0);
    else
        snprintf(err, sizeof(err), "snapshot_path_missing");

    if (restored) {
        st = NULL;
        if (sqlite3_prepare_v2(db,
                "UPDATE config_apply_tasks SET state='rolled_back',finished_at=?1,"
                "error='auto_rollback_applied_by_dreamingwrt_init',"
                "rollback_applied=1,rollback_error='' "
                "WHERE id=?2 AND state='pending'",
                -1, &st, NULL) == SQLITE_OK) {
            sqlite3_bind_int64(st, 1, now);
            sqlite3_bind_int(st, 2, id);
            if (sqlite3_step(st) == SQLITE_DONE && sqlite3_changes(db) > 0)
                r->rolled_back++;
            else
                r->failed++;
            sqlite3_finalize(st);
            return 0;
        }
    } else {
        st = NULL;
        if (sqlite3_prepare_v2(db,
                "UPDATE config_apply_tasks SET state='rollback_failed',finished_at=?1,"
                "error='auto_rollback_failed_by_dreamingwrt_init',"
                "rollback_applied=0,rollback_error=?2 "
                "WHERE id=?3 AND state='pending'",
                -1, &st, NULL) == SQLITE_OK) {
            sqlite3_bind_int64(st, 1, now);
            sqlite3_bind_text(st, 2, err, -1, SQLITE_TRANSIENT);
            sqlite3_bind_int(st, 3, id);
            sqlite3_step(st);
            sqlite3_finalize(st);
        }
        r->failed++;
        return -1;
    }

    snprintf(r->error, sizeof(r->error), "sqlite_update_failed:%s", sqlite3_errmsg(db));
    r->failed++;
    return -1;
}

static int auto_rollback_scan(struct rollback_scan_result *r)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *st = NULL;
    int rc;
    int64_t now = (int64_t)time(NULL);

    if (!r)
        return -1;
    memset(r, 0, sizeof(*r));
    rc = sqlite3_open_v2(DWRT_APP_DB, &db, SQLITE_OPEN_READWRITE, NULL);
    if (rc != SQLITE_OK) {
        snprintf(r->error, sizeof(r->error), "open_config_db_failed:%s",
                 db ? sqlite3_errmsg(db) : "sqlite unavailable");
        if (db)
            sqlite3_close(db);
        return -1;
    }
    r->available = 1;
    sqlite3_busy_timeout(db, 1000);
    if (!config_apply_table_exists(db)) {
        snprintf(r->error, sizeof(r->error), "config_apply_tasks_missing");
        sqlite3_close(db);
        return 0;
    }
    if (sqlite3_prepare_v2(db,
            "SELECT id,started_at,rollback_timeout,snapshot_path,snapshot_ok,scope "
            "FROM config_apply_tasks WHERE state='pending' "
            "ORDER BY id ASC LIMIT 50",
            -1, &st, NULL) != SQLITE_OK) {
        snprintf(r->error, sizeof(r->error), "select_pending_failed:%s", sqlite3_errmsg(db));
        sqlite3_close(db);
        return -1;
    }
    while (sqlite3_step(st) == SQLITE_ROW) {
        int id = sqlite3_column_int(st, 0);
        int64_t started_at = sqlite3_column_int64(st, 1);
        int timeout = sqlite3_column_int(st, 2);
        const char *snapshot = (const char *)sqlite3_column_text(st, 3);
        int snapshot_ok = sqlite3_column_int(st, 4);

        r->scanned++;
        if (timeout < 10)
            timeout = 10;
        if (timeout > 86400)
            timeout = 86400;
        if (started_at <= 0 || now < started_at + timeout) {
            r->skipped++;
            continue;
        }
        r->expired++;
        if (!snapshot_ok || !snapshot || !snapshot[0]) {
            (void)auto_rollback_one(db, id, "", r);
            continue;
        }
        (void)auto_rollback_one(db, id, snapshot, r);
    }
    sqlite3_finalize(st);
    sqlite3_close(db);
    return r->failed > 0 ? -1 : 0;
}

static void emit_rollback_scan_result(struct outbuf *out,
                                      const struct rollback_scan_result *r,
                                      int json)
{
    if (!out || !r)
        return;
    if (json) {
        ob_appendf(out,
                   "{\"ok\": %s, \"worker\": \"dreamingwrt-init\", "
                   "\"app_db\": \"%s\", \"config_db\": \"%s\", \"network_config\": \"%s\", "
                   "\"available\": %s, \"scanned\": %d, \"expired\": %d, "
                   "\"rolled_back\": %d, \"failed\": %d, \"skipped\": %d, "
                   "\"error\": ",
                   r->failed ? "false" : "true",
                   DWRT_APP_DB, DWRT_CONFIG_DB, DWRT_NETWORK_CONFIG,
                   r->available ? "true" : "false",
                   r->scanned, r->expired, r->rolled_back,
                   r->failed, r->skipped);
        ob_append_json_string(out, r->error);
        ob_appendf(out, "}\n");
        return;
    }
    ob_appendf(out,
               "rollback-scan: available=%s scanned=%d expired=%d rolled_back=%d failed=%d skipped=%d error=\"%s\"\n",
               r->available ? "yes" : "no",
               r->scanned, r->expired, r->rolled_back,
               r->failed, r->skipped, r->error);
}

static void maybe_auto_rollback_scan(void)
{
    time_t now = time(NULL);
    struct rollback_scan_result r;

    if (g_last_rollback_scan_at > 0 &&
        now - g_last_rollback_scan_at < DWRT_AUTO_ROLLBACK_POLL_SEC)
        return;
    g_last_rollback_scan_at = now;
    if (auto_rollback_scan(&r) == 0 && r.rolled_back > 0) {
        fprintf(stderr, "dreamingwrt-init: auto-rollback rolled_back=%d scanned=%d expired=%d\n",
                r.rolled_back, r.scanned, r.expired);
    } else if (r.failed > 0) {
        fprintf(stderr, "dreamingwrt-init: auto-rollback scan failed=%d error=%s\n",
                r.failed, r.error);
    }
}

static void disable_nf_deaf(void)
{
    run_shell_quiet("nft delete table inet nf_deaf_custom 2>/dev/null");
    run_shell_quiet("rmmod nf_deaf 2>/dev/null");
}

static void ensure_jmx_module(void)
{
    run_shell_quiet("lsmod | grep -q '^jmx ' || modprobe jmx 2>/dev/null || true");
}

static void wait_audit_sources(void)
{
    int i;
    ensure_jmx_module();
    for (i = 0; i < 5; i++) {
        struct stat st;
        if (stat("/proc/dreamingwrt/jmx", &st) == 0 && S_ISDIR(st.st_mode))
            return;
        sleep(1);
    }
}

static void prepare_component(const struct component *c)
{
    if (c->prepare_flags & PREP_CORE) {
        disable_nf_deaf();
        ensure_jmx_module();
    }
    if (c->prepare_flags & PREP_AUDIT)
        wait_audit_sources();
}


static void apply_component_env_defaults(const struct component *c)
{
    size_t i;

    if (!c)
        return;
    for (i = 0; i < ARRAY_SIZE(c->env_defaults) && c->env_defaults[i]; i++) {
        const char *item = c->env_defaults[i];
        const char *eq = strchr(item, '=');
        char key[96];
        size_t key_len;

        if (!eq || eq == item)
            continue;
        key_len = (size_t)(eq - item);
        if (key_len >= sizeof(key))
            continue;
        memcpy(key, item, key_len);
        key[key_len] = '\0';
        if (!getenv(key) || !getenv(key)[0])
            setenv(key, eq + 1, 1);
    }
}

static int build_argv(const struct component *c, const char *path, char **argv, size_t max_args)
{
    size_t n = 0;
    size_t i;
    const char *port;
    const char *bind;

    if (max_args < 2)
        return -1;
    argv[n++] = (char *)path;

    if (strcmp(c->name, "dreamingwrt-webd") == 0) {
        port = getenv("WEBD_PORT");
        bind = getenv("WEBD_BIND");
        argv[n++] = (char *)(port && port[0] ? port : "12517");
        argv[n++] = (char *)(bind && bind[0] ? bind : "0.0.0.0");
    } else {
        for (i = 0; i < ARRAY_SIZE(c->args) && c->args[i]; i++) {
            if (n + 1 >= max_args)
                break;
            argv[n++] = (char *)c->args[i];
        }
    }
    argv[n] = NULL;
    return 0;
}

static int start_component(struct component *c, struct outbuf *out, int quiet)
{
    const char *path;
    char *argv[8];
    pid_t existing;
    pid_t pid;

    if (!c)
        return -1;
    c->desired = 1;

    if (c->pid > 0 && kill(c->pid, 0) == 0) {
        cleanup_component_orphans(c, c->pid, out, quiet);
        if (!quiet)
            ob_appendf(out, "%s already running pid=%ld\n", c->name, (long)c->pid);
        return 0;
    }
    c->pid = 0;

    existing = find_component_pid(c);
    if (existing > 0) {
        /* Do not adopt a process left by an older supervisor generation.
         * Core/webd may still own NFQUEUE, ubus, sockets or SQLite WAL locks;
         * stop leftovers first, then fork a child this supervisor can reap. */
        cleanup_component_orphans(c, 0, out, quiet);
        existing = find_component_pid(c);
        if (existing > 0) {
            if (!quiet)
                ob_appendf(out, "%s orphan process still running pid=%ld\n", c->name, (long)existing);
            c->next_respawn_at = time(NULL) + 5;
            return -1;
        }
    }

    path = select_exec_path(c);
    if (!path) {
        c->next_respawn_at = time(NULL) + 60;
        if (!quiet)
            ob_appendf(out, "%s missing executable %s\n", c->name, c->path);
        return -1;
    }

    prepare_component(c);
    if (build_argv(c, path, argv, ARRAY_SIZE(argv)) != 0) {
        if (!quiet)
            ob_appendf(out, "%s cannot build argv\n", c->name);
        return -1;
    }

    pid = fork();
    if (pid < 0) {
        if (!quiet)
            ob_appendf(out, "%s fork failed: %s\n", c->name, strerror(errno));
        return -1;
    }
    if (pid == 0) {
        int fd;
        setsid();
        fd = open("/dev/null", O_RDONLY);
        if (fd >= 0) {
            dup2(fd, STDIN_FILENO);
            close(fd);
        }
        /*
         * The supervisor handles start/stop over a Unix socket.  Children
         * spawned while serving a command must not inherit either the listen fd
         * or that command's accepted cfd, otherwise the CLI waits for EOF until
         * the daemon exits.  Close everything except stdio before exec; daemons
         * open their own ubus/db/socket descriptors afterwards.
         */
        apply_component_env_defaults(c);
        close_exec_extra_fds();
        execv(path, argv);
        if (c->alias_path && strcmp(path, c->alias_path) != 0 && file_exists_exec(c->alias_path)) {
            argv[0] = (char *)c->alias_path;
            execv(c->alias_path, argv);
        }
        fprintf(stderr, "dreamingwrt-init: exec %s failed: %s\n", path, strerror(errno));
        _exit(127);
    }

    c->pid = pid;
    c->started_at = time(NULL);
    c->next_respawn_at = 0;
    c->backoff_sec = 0;
    c->restart_count++;
    if (!quiet)
        ob_appendf(out, "%s started pid=%ld\n", c->name, (long)pid);
    return 0;
}

static int stop_component(struct component *c, struct outbuf *out, int quiet)
{
    int waited = 0;
    int timeout;

    if (!c)
        return -1;
    c->desired = 0;

    if (count_component_pids(c) <= 0) {
        c->pid = 0;
        if (!quiet)
            ob_appendf(out, "%s already stopped\n", c->name);
        return 0;
    }

    signal_component_pids(c, SIGTERM);
    timeout = c->stop_timeout_sec > 0 ? c->stop_timeout_sec : 4;
    while (waited < timeout) {
        if (count_component_pids(c) <= 0) {
            c->pid = 0;
            if (!quiet)
                ob_appendf(out, "%s stopped\n", c->name);
            return 0;
        }
        sleep(1);
        waited++;
    }

    signal_component_pids(c, SIGKILL);
    sleep(1);
    cleanup_component_orphans(c, 0, out, 1);
    c->pid = 0;
    if (!quiet)
        ob_appendf(out, "%s killed\n", c->name);
    return 0;
}

static void start_all(struct outbuf *out, int quiet)
{
    size_t i;
    for (i = 0; i < ARRAY_SIZE(g_components); i++) {
        if (g_components[i].enabled)
            start_component(&g_components[i], out, quiet);
    }
}

static void stop_all(struct outbuf *out, int quiet)
{
    size_t i = ARRAY_SIZE(g_components);
    while (i-- > 0)
        stop_component(&g_components[i], out, quiet);
}

static int config_restore_stop_all(void *opaque)
{
    struct outbuf *out = opaque;

    stop_all(out, 1);
    return 0;
}

static int config_restore_start_core(void *opaque)
{
    struct outbuf *out = opaque;
    struct component *core = find_component("dreamingwrt-core");

    return core ? start_component(core, out, 1) : -1;
}

static int config_restore_start_all(void *opaque)
{
    struct outbuf *out = opaque;

    start_all(out, 1);
    return 0;
}

static void config_restore_hooks(struct dwrt_config_restore_hooks *hooks,
                                 struct outbuf *out)
{
    memset(hooks, 0, sizeof(*hooks));
    hooks->stop_all = config_restore_stop_all;
    hooks->start_core = config_restore_start_core;
    hooks->start_all = config_restore_start_all;
    hooks->opaque = out;
}

static int maybe_apply_armed_config_restore(const char *trigger)
{
    struct dwrt_config_restore_hooks hooks;
    struct dwrt_config_restore_info info;
    struct outbuf out;
    int rc;

    if (dwrt_config_restore_status(&info) != 0 || !info.pending ||
        strcmp(info.phase, "armed"))
        return 0;
    if (info.operation_id[0] &&
        !strcmp(g_config_restore_attempted_operation, info.operation_id))
        return 0;

    snprintf(g_config_restore_attempted_operation,
             sizeof(g_config_restore_attempted_operation), "%s",
             info.operation_id);
    ob_init(&out);
    config_restore_hooks(&hooks, &out);
    rc = dwrt_config_restore_apply(&hooks, &info);
    ob_free(&out);
    if (rc == 0) {
        g_config_restore_applied_at_boot = 1;
        fprintf(stderr,
                "dreamingwrt-init: config restore applied trigger=%s operation=%s expected_lan_ip=%s deadline=%lld\n",
                trigger ? trigger : "unknown", info.operation_id,
                info.expected_lan_ip, (long long)info.deadline);
        return 1;
    }

    /* A validation failure can happen before apply starts the components. */
    ob_init(&out);
    start_all(&out, 1);
    ob_free(&out);
    fprintf(stderr,
            "dreamingwrt-init: config restore failed trigger=%s phase=%s operation=%s error=%s\n",
            trigger ? trigger : "unknown", info.phase, info.operation_id,
            info.error);
    return -1;
}

static void emit_config_restore_info(struct outbuf *out,
                                     const struct dwrt_config_restore_info *info,
                                     int ok, int json)
{
    if (!out || !info)
        return;
    if (!json) {
        ob_appendf(out,
            "config-restore: ok=%s phase=%s operation_id=%s pending=%s backup=%s "
            "size=%llu sha256=%s expected_lan_ip=%s wan_count=%d lan_count=%d "
            "started_at=%lld deadline=%lld error=%s\n",
            ok ? "yes" : "no", info->phase, info->operation_id,
            info->pending ? "yes" : "no", info->backup_available ? "yes" : "no",
            (unsigned long long)info->size_bytes, info->source_sha256,
            info->expected_lan_ip, info->wan_count, info->lan_count,
            (long long)info->started_at, (long long)info->deadline, info->error);
        return;
    }
    ob_appendf(out, "{\"ok\":%s,\"service\":\"dreamingwrt-init\",\"format\":\"%s\",",
               ok ? "true" : "false", DWRT_CONFIG_RESTORE_FORMAT);
    ob_appendf(out, "\"phase\":");
    ob_append_json_string(out, info->phase);
    ob_appendf(out, ",\"operation_id\":");
    ob_append_json_string(out, info->operation_id);
    ob_appendf(out, ",\"pending\":%s,\"backup_available\":%s,\"size_bytes\":%llu,",
               info->pending ? "true" : "false",
               info->backup_available ? "true" : "false",
               (unsigned long long)info->size_bytes);
    ob_appendf(out, "\"sha256\":");
    ob_append_json_string(out, info->source_sha256);
    ob_appendf(out, ",\"expected_lan_ip\":");
    ob_append_json_string(out, info->expected_lan_ip);
    ob_appendf(out, ",\"wan_count\":%d,\"lan_count\":%d,\"started_at\":%lld,"
               "\"deadline\":%lld,\"confirm_window_seconds\":%d,\"error\":",
               info->wan_count, info->lan_count, (long long)info->started_at,
               (long long)info->deadline, DWRT_CONFIG_RESTORE_CONFIRM_SECONDS);
    ob_append_json_string(out, info->error);
    ob_appendf(out, "}\n");
}

static int handle_config_restore_command(const char *action, int force, int json,
                                         struct outbuf *out)
{
    struct dwrt_config_restore_info info;
    struct dwrt_config_restore_hooks hooks;
    int rc;

    memset(&info, 0, sizeof(info));
    config_restore_hooks(&hooks, out);
    if (!action || !action[0] || !strcmp(action, "status")) {
        rc = dwrt_config_restore_status(&info);
    } else if (!strcmp(action, "arm")) {
        rc = dwrt_config_restore_arm(&info);
    } else if (!strcmp(action, "apply")) {
        if (!force) {
            snprintf(info.phase, sizeof(info.phase), "refused");
            snprintf(info.error, sizeof(info.error), "config_restore_apply_requires_force");
            emit_config_restore_info(out, &info, 0, json);
            return 1;
        }
        rc = dwrt_config_restore_apply(&hooks, &info);
    } else if (!strcmp(action, "confirm")) {
        rc = dwrt_config_restore_confirm(&info);
    } else if (!strcmp(action, "rollback")) {
        rc = dwrt_config_restore_rollback(&hooks, "manual_rollback", &info);
    } else {
        snprintf(info.phase, sizeof(info.phase), "refused");
        snprintf(info.error, sizeof(info.error), "unknown_config_restore_action");
        emit_config_restore_info(out, &info, 0, json);
        return 1;
    }
    emit_config_restore_info(out, &info, rc == 0, json);
    return rc == 0 ? 0 : 1;
}

static int set_component_enabled(struct outbuf *out, const char *target,
                                 int enabled, int force, int json)
{
    size_t i;
    int changed = 0;
    int matched = 0;

    if (!target || !target[0])
        target = "all";
    if (!enabled && !strcmp(target, "all") && !force) {
        if (json)
            ob_appendf(out, "{\"ok\": false, \"error\": \"disable_all_requires_force\", \"config_path\": \"%s\"}\n",
                       DWRT_INIT_CONFIG);
        else
            ob_appendf(out, "error: disable all requires --force\n");
        return 1;
    }

    for (i = 0; i < ARRAY_SIZE(g_components); i++) {
        struct component *c = &g_components[i];

        if (strcmp(target, "all") != 0 && !component_name_matches(c, target))
            continue;
        matched++;
        if (!enabled && c->critical && !force) {
            if (json)
                ob_appendf(out, "{\"ok\": false, \"error\": \"critical_component_requires_force\", \"component\": \"%s\", \"config_path\": \"%s\"}\n",
                           c->name, DWRT_INIT_CONFIG);
            else
                ob_appendf(out, "error: %s is critical; use --force to persistently disable it\n", c->name);
            return 1;
        }
        if (c->enabled != enabled) {
            c->enabled = enabled;
            changed++;
        }
        if (!enabled)
            c->desired = 0;
    }

    if (!matched) {
        if (json)
            ob_appendf(out, "{\"ok\": false, \"error\": \"unknown_component\", \"component\": ");
        if (json) {
            ob_append_json_string(out, target);
            ob_appendf(out, "}\n");
        } else {
            ob_appendf(out, "error: unknown component %s\n", target);
        }
        return 1;
    }

    if (save_config() != 0) {
        if (json)
            ob_appendf(out, "{\"ok\": false, \"error\": \"config_save_failed\", \"config_path\": \"%s\"}\n",
                       DWRT_INIT_CONFIG);
        else
            ob_appendf(out, "error: cannot save %s: %s\n", DWRT_INIT_CONFIG, strerror(errno));
        return 1;
    }

    if (json) {
        ob_appendf(out,
                   "{\"ok\": true, \"action\": \"%s\", \"target\": ",
                   enabled ? "enable" : "disable");
        ob_append_json_string(out, target);
        ob_appendf(out,
                   ", \"changed\": %d, \"matched\": %d, \"config_path\": \"%s\", \"note\": \"persistent policy only; running processes are unchanged\"}\n",
                   changed, matched, DWRT_INIT_CONFIG);
    } else {
        ob_appendf(out,
                   "%s %s: matched=%d changed=%d config=%s (persistent policy only; running processes unchanged)\n",
                   enabled ? "enabled" : "disabled",
                   target, matched, changed, DWRT_INIT_CONFIG);
    }
    return 0;
}

static void reap_children(void)
{
    int status;
    pid_t pid;
    size_t i;
    time_t now = time(NULL);

    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
        for (i = 0; i < ARRAY_SIZE(g_components); i++) {
            if (g_components[i].pid == pid) {
                int backoff;
                fprintf(stderr, "dreamingwrt-init: %s exited pid=%ld status=%d\n",
                        g_components[i].name, (long)pid, status);
                g_components[i].last_exit_at = now;
                g_components[i].last_exit_status = status;
                g_components[i].last_exit_code = decode_exit_code(status);
                g_components[i].last_exit_signal = decode_exit_signal(status);
                backoff = next_backoff_sec(&g_components[i], now);
                g_components[i].pid = 0;
                g_components[i].started_at = 0;
                g_components[i].next_respawn_at = now + backoff;
                break;
            }
        }
    }
}

static void supervise_components(void)
{
    size_t i;
    time_t now = time(NULL);
    struct outbuf dummy;

    ob_init(&dummy);
    for (i = 0; i < ARRAY_SIZE(g_components); i++) {
        struct component *c = &g_components[i];
        pid_t pid;
        if (!c->desired)
            continue;
        if (c->pid > 0 && kill(c->pid, 0) == 0) {
            cleanup_component_orphans(c, c->pid, &dummy, 1);
            if (component_uptime_sec(c, now) >= 60) {
                c->crash_count = 0;
                c->backoff_sec = 0;
            }
            continue;
        }
        pid = find_component_pid(c);
        if (pid > 0) {
            cleanup_component_orphans(c, 0, &dummy, 1);
            c->pid = 0;
            if (component_respawn_in_sec(c, now) > 0)
                continue;
        }
        c->pid = 0;
        if (component_respawn_in_sec(c, now) > 0)
            continue;
        if (!select_exec_path(c)) {
            c->next_respawn_at = now + 60;
            continue;
        }
        start_component(c, &dummy, 1);
        c->next_respawn_at = now + 5;
    }
    ob_free(&dummy);
}

static const char *component_state(const struct component *c, pid_t *pid_out, int *supervised_out)
{
    pid_t pid = 0;
    int supervised = 0;

    if (c->pid > 0 && kill(c->pid, 0) == 0) {
        pid = c->pid;
        supervised = 1;
    } else {
        pid = find_component_pid(c);
    }
    if (pid_out)
        *pid_out = pid;
    if (supervised_out)
        *supervised_out = supervised;
    if (pid > 0)
        return supervised ? "running" : "running-external";
    if (!select_exec_path(c))
        return "missing";
    return "stopped";
}

static int module_loaded(const char *name)
{
    char buf[8192];
    int n;
    char *line;
    char *saveptr = NULL;

    n = read_file("/proc/modules", buf, sizeof(buf));
    if (n <= 0)
        return 0;
    line = strtok_r(buf, "\n", &saveptr);
    while (line) {
        size_t len = strlen(name);
        if (strncmp(line, name, len) == 0 && isspace((unsigned char)line[len]))
            return 1;
        line = strtok_r(NULL, "\n", &saveptr);
    }
    return 0;
}

static void emit_components_plain(struct outbuf *out, const char *only)
{
    size_t i;
    time_t now = time(NULL);
    int emit_all = !only || strcmp(only, "all") == 0;
    for (i = 0; i < ARRAY_SIZE(g_components); i++) {
        struct component *c = &g_components[i];
        pid_t pid = 0;
        int supervised = 0;
        const char *state;
        const char *path;
        long uptime;
        long respawn_in = 0;

        if (!emit_all && !component_name_matches(c, only))
            continue;
        path = select_exec_path(c);
        state = component_state(c, &pid, &supervised);
        uptime = component_reported_uptime_sec(c, pid, supervised, now);
        respawn_in = component_respawn_in_sec(c, now);
        ob_appendf(out, "%-24s %-16s short=%-12s pid=%-6ld supervised=%s uptime=%lds restarts=%d crashes=%d next_respawn=%lds path=%s\n",
                   c->name, state, short_name(c), (long)pid, supervised ? "yes" : "no",
                   uptime, c->restart_count, c->crash_count, respawn_in, path ? path : c->path);
    }
}

static void emit_storage_plain(struct outbuf *out)
{
    struct storage_backend_status bs;
    struct storage_summary st;
    int i;

    if (storage_backend_status_collect(&bs) == 0) {
        ob_appendf(out, "storage: source=core level=%s reason=\"%s\"\n",
                   bs.health[0] ? bs.health : "unknown",
                   bs.reason[0] ? bs.reason : "storage_status_from_core");
        storage_backend_status_free(&bs);
        return;
    }
    storage_backend_status_free(&bs);

    storage_summary_collect(&st);
    ob_appendf(out,
               "storage: source=local_scan level=%s reason=\"%s\" total=%llu db=%llu wal=%llu largest=%llu largest_path=%s files=%d\n",
               st.level, st.reason,
               st.total_bytes, st.db_bytes, st.wal_bytes,
               st.largest_bytes, st.largest_path[0] ? st.largest_path : "-",
               st.file_count);
    for (i = 0; i < st.fs_count; i++) {
        if (!st.fs[i].ok)
            continue;
        ob_appendf(out,
                   "storage.fs.%s: path=%s used=%d%% used_bytes=%llu avail_bytes=%llu total_bytes=%llu\n",
                   st.fs[i].name, st.fs[i].path, st.fs[i].used_pct,
                   st.fs[i].used_bytes, st.fs[i].avail_bytes, st.fs[i].total_bytes);
    }
}

static void emit_storage_json_members(struct outbuf *out, struct storage_summary *st)
{
    int i;

    ob_appendf(out,
        "\"storage\": {\"level\": \"%s\", \"reason\": \"%s\", \"total_bytes\": %llu, \"db_bytes\": %llu, \"wal_bytes\": %llu, \"shm_bytes\": %llu, \"other_bytes\": %llu, \"file_count\": %d, \"db_count\": %d, \"wal_count\": %d, \"shm_count\": %d, \"largest_bytes\": %llu, \"largest_path\": \"%s\", \"filesystems\": [",
        st->level, st->reason,
        st->total_bytes, st->db_bytes, st->wal_bytes, st->shm_bytes, st->other_bytes,
        st->file_count, st->db_count, st->wal_count, st->shm_count,
        st->largest_bytes, st->largest_path);
    for (i = 0; i < st->fs_count; i++) {
        ob_appendf(out,
            "%s{\"name\": \"%s\", \"path\": \"%s\", \"ok\": %s, \"used_pct\": %d, \"total_bytes\": %llu, \"used_bytes\": %llu, \"avail_bytes\": %llu}",
            i ? ", " : "",
            st->fs[i].name, st->fs[i].path,
            st->fs[i].ok ? "true" : "false",
            st->fs[i].used_pct,
            st->fs[i].total_bytes,
            st->fs[i].used_bytes,
            st->fs[i].avail_bytes);
    }
    ob_appendf(out, "]}");
}

static void emit_storage_json_fallback_members(struct outbuf *out)
{
    struct storage_backend_status bs;
    struct storage_summary st;

    if (storage_backend_status_collect(&bs) == 0) {
        ob_appendf(out, "\"storage_source\": \"core\", \"storage\": ");
        ob_append_mem(out, bs.data_json, strlen(bs.data_json));
        storage_backend_status_free(&bs);
        return;
    }

    storage_summary_collect(&st);
    ob_appendf(out, "\"storage_source\": \"local_scan\", \"storage_error\": ");
    ob_append_json_string(out, bs.error[0] ? bs.error : "core_storage_status_unavailable");
    ob_appendf(out, ", ");
    emit_storage_json_members(out, &st);
    storage_backend_status_free(&bs);
}

static void emit_components_json(struct outbuf *out, const char *only, int include_storage)
{
    size_t i;
    int first = 1;
    time_t now = time(NULL);
    int emit_all = !only || strcmp(only, "all") == 0;

    ob_appendf(out, "{\n  \"ok\": true,\n  \"version\": \"%s\",\n  \"supervisor\": {\"running\": %s, \"pid\": %ld, \"socket\": \"%s\"},\n  \"components\": [",
               DWRT_INIT_VERSION,
               g_supervisor_mode ? "true" : "false",
               g_supervisor_mode ? (long)getpid() : 0L,
               g_socket_path);
    for (i = 0; i < ARRAY_SIZE(g_components); i++) {
        struct component *c = &g_components[i];
        pid_t pid = 0;
        int supervised = 0;
        const char *state;
        const char *path;
        long uptime;
        long respawn_in = 0;

        if (!emit_all && !component_name_matches(c, only))
            continue;
        path = select_exec_path(c);
        state = component_state(c, &pid, &supervised);
        uptime = component_reported_uptime_sec(c, pid, supervised, now);
        respawn_in = component_respawn_in_sec(c, now);
        ob_appendf(out,
            "%s\n    {\"name\": \"%s\", \"short\": \"%s\", \"alias\": ",
            first ? "" : ",",
            c->name,
            short_name(c));
        if (c->alias_name)
            ob_appendf(out, "\"%s\"", c->alias_name);
        else
            ob_appendf(out, "null");
        ob_appendf(out,
            ", \"state\": \"%s\", \"pid\": %ld, \"supervised\": %s, \"enabled\": %s, \"critical\": %s, \"path\": \"%s\", \"installed\": %s, \"desired\": %s, \"uptime_sec\": %ld, \"restart_count\": %d, \"crash_count\": %d, \"backoff_sec\": %d, \"next_respawn_in_sec\": %ld, \"last_exit_at\": %ld, \"last_exit_status\": %d, \"last_exit_code\": %d, \"last_exit_signal\": %d}",
            state,
            (long)pid,
            supervised ? "true" : "false",
            c->enabled ? "true" : "false",
            c->critical ? "true" : "false",
            path ? path : c->path,
            path ? "true" : "false",
            c->desired ? "true" : "false",
            uptime,
            c->restart_count,
            c->crash_count,
            c->backoff_sec,
            respawn_in,
            (long)c->last_exit_at,
            c->last_exit_status,
            c->last_exit_code,
            c->last_exit_signal);
        first = 0;
    }
    ob_appendf(out, "\n  ]");
    if (include_storage) {
        ob_appendf(out, ",\n  ");
        emit_storage_json_fallback_members(out);
    }
    ob_appendf(out, "\n}\n");
}

static void emit_list_json(struct outbuf *out)
{
    size_t i;
    ob_appendf(out, "{\n  \"ok\": true,\n  \"components\": [");
    for (i = 0; i < ARRAY_SIZE(g_components); i++) {
        struct component *c = &g_components[i];
        ob_appendf(out,
            "%s\n    {\"name\": \"%s\", \"short\": \"%s\", \"alias\": ",
            i ? "," : "",
            c->name,
            short_name(c));
        if (c->alias_name)
            ob_appendf(out, "\"%s\"", c->alias_name);
        else
            ob_appendf(out, "null");
        ob_appendf(out,
            ", \"path\": \"%s\", \"enabled\": %s, \"critical\": %s}",
            c->path,
            c->enabled ? "true" : "false",
            c->critical ? "true" : "false");
    }
    ob_appendf(out, "\n  ]\n}\n");
}

static int emit_check(struct outbuf *out, int json)
{
    size_t i;
    int running = 0;
    int missing = 0;
    int critical_failed = 0;
    int module_ok;
    int ok;

    for (i = 0; i < ARRAY_SIZE(g_components); i++) {
        pid_t pid = 0;
        const char *state = component_state(&g_components[i], &pid, NULL);
        if (pid > 0)
            running++;
        if (strcmp(state, "missing") == 0)
            missing++;
        if (g_components[i].enabled && g_components[i].critical && pid <= 0)
            critical_failed++;
    }
    module_ok = module_loaded("jmx");
    ok = g_supervisor_mode && module_ok && critical_failed == 0;

    if (json) {
        ob_appendf(out,
            "{\n"
            "  \"ok\": %s,\n"
            "  \"version\": \"%s\",\n"
            "  \"socket\": \"%s\",\n"
            "  \"supervisor_running\": %s,\n"
            "  \"jmx_module_loaded\": %s,\n"
            "  \"signature_authority\": \"dreamingwrt_signatures.db\",\n"
            "  \"components_running\": %d,\n"
            "  \"components_total\": %zu,\n"
            "  \"components_missing\": %d,\n"
            "  \"critical_components_failed\": %d,\n"
            "  ",
            ok ? "true" : "false",
            DWRT_INIT_VERSION,
            g_socket_path,
            g_supervisor_mode ? "true" : "false",
            module_loaded("jmx") ? "true" : "false",
            running,
            ARRAY_SIZE(g_components),
            missing,
            critical_failed);
        emit_storage_json_fallback_members(out);
        ob_appendf(out, "\n}\n");
        return ok ? 0 : 1;
    }

    ob_appendf(out, "dreamingwrt-init %s\n", DWRT_INIT_VERSION);
    ob_appendf(out, "supervisor: %s pid=%ld socket=%s\n",
               g_supervisor_mode ? "running" : "not-connected",
               (long)getpid(), g_socket_path);
    ob_appendf(out, "jmx_module: %s\n", module_loaded("jmx") ? "loaded" : "missing");
    ob_appendf(out, "signature_authority: dreamingwrt_signatures.db\n");
    ob_appendf(out, "components: running=%d total=%zu missing=%d\n",
               running, ARRAY_SIZE(g_components), missing);
    ob_appendf(out, "critical: failed=%d overall=%s\n",
               critical_failed, ok ? "healthy" : "unhealthy");
    emit_storage_plain(out);
    return ok ? 0 : 1;
}

static int handle_command(char *line, struct outbuf *out)
{
    char *argv[8];
    int argc = 0;
    char *saveptr = NULL;
    char *tok;
    int json = 0;
    int force = 0;
    int no_storage = 0;
    const char *cmd;
    const char *target;

    tok = strtok_r(line, " \t\r\n", &saveptr);
    while (tok && argc < (int)ARRAY_SIZE(argv)) {
        if (strcmp(tok, "--json") == 0)
            json = 1;
        else if (strcmp(tok, "--no-storage") == 0)
            no_storage = 1;
        else if (strcmp(tok, "--force") == 0)
            force = 1;
        else
            argv[argc++] = tok;
        tok = strtok_r(NULL, " \t\r\n", &saveptr);
    }
    if (argc == 0) {
        ob_appendf(out, "error: empty command\n");
        return 1;
    }

    cmd = argv[0];
    target = argc >= 2 ? argv[1] : "all";

    if (strcmp(cmd, "list") == 0) {
        if (json)
            emit_list_json(out);
        else
            emit_components_plain(out, "all");
        return 0;
    }

    if (strcmp(cmd, "status") == 0) {
        if (strcmp(target, "all") != 0 && !find_component(target)) {
            ob_appendf(out, "error: unknown component %s\n", target);
            return 1;
        }
        if (json)
            emit_components_json(out, target, !no_storage);
        else {
            emit_components_plain(out, target);
            emit_storage_plain(out);
        }
        return 0;
    }

    if (strcmp(cmd, "check") == 0) {
        return emit_check(out, json);
    }

    if (strcmp(cmd, "rollback-scan") == 0 || strcmp(cmd, "rollback_scan") == 0) {
        struct rollback_scan_result r;

        auto_rollback_scan(&r);
        emit_rollback_scan_result(out, &r, json);
        return r.failed > 0 ? 1 : 0;
    }

    if (strcmp(cmd, "system-db") == 0 || strcmp(cmd, "system_db") == 0) {
        const char *action = argc >= 2 ? argv[1] : "status";
        int rc;

        if (!strcmp(action, "status"))
            return emit_system_db_status(out, 0, json, NULL);
        if (!strcmp(action, "sync")) {
            int conflicts = 0;

            stop_all(out, 1);
            rc = emit_system_db_status(out, 1, json, &conflicts);
            if (!conflicts)
                start_all(out, 1);
            else if (!json)
                ob_appendf(out,
                           "components remain stopped: system database source conflict\n");
            return rc;
        }
        ob_appendf(out, "error: usage: dreamingwrt-init system-db status|sync [--json]\n");
        return 1;
    }

    if (strcmp(cmd, "config-restore") == 0 || strcmp(cmd, "config_restore") == 0)
        return handle_config_restore_command(argc >= 2 ? argv[1] : "status",
                                             force, json, out);

    if (strcmp(cmd, "enable") == 0 || strcmp(cmd, "disable") == 0) {
        if (argc < 2) {
            ob_appendf(out, "error: usage: dreamingwrt-init %s <component|all> [--force]\n", cmd);
            return 1;
        }
        return set_component_enabled(out, target, strcmp(cmd, "enable") == 0, force, json);
    }

    if (strcmp(cmd, "start") == 0) {
        if (strcmp(target, "all") == 0)
            start_all(out, 0);
        else {
            struct component *c = find_component(target);
            if (!c) {
                ob_appendf(out, "error: unknown component %s\n", target);
                return 1;
            }
            start_component(c, out, 0);
        }
        return 0;
    }

    if (strcmp(cmd, "stop") == 0) {
        if (strcmp(target, "all") == 0)
            stop_all(out, 0);
        else {
            struct component *c = find_component(target);
            if (!c) {
                ob_appendf(out, "error: unknown component %s\n", target);
                return 1;
            }
            stop_component(c, out, 0);
        }
        return 0;
    }

    if (strcmp(cmd, "restart") == 0) {
        if (strcmp(target, "all") == 0) {
            stop_all(out, 0);
            start_all(out, 0);
        } else {
            struct component *c = find_component(target);
            if (!c) {
                ob_appendf(out, "error: unknown component %s\n", target);
                return 1;
            }
            stop_component(c, out, 0);
            start_component(c, out, 0);
        }
        return 0;
    }

    ob_appendf(out, "error: unknown command %s\n", cmd);
    return 1;
}

static int setup_socket(const char *sock_path)
{
    int fd;
    struct sockaddr_un addr;

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;
    set_fd_cloexec(fd);

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", sock_path);

    unlink(sock_path);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        return -1;
    }
    chmod(sock_path, 0600);
    if (listen(fd, 8) != 0) {
        close(fd);
        unlink(sock_path);
        return -1;
    }
    return fd;
}

static void serve_client(int cfd)
{
    char line[512];
    ssize_t n;
    struct outbuf out;
    int rc;

    n = read(cfd, line, sizeof(line) - 1);
    if (n <= 0)
        return;
    line[n] = '\0';

    ob_init(&out);
    rc = handle_command(line, &out);
    if (out.data && out.len)
        (void)write(cfd, out.data, out.len);
    if (rc != 0)
        (void)write(cfd, "", 0);
    ob_free(&out);
}

static int run_supervisor(const char *sock_path)
{
    struct sigaction sa;
    struct outbuf dummy;
    struct dwrt_config_restore_info restore_info;
    int restore_apply_rc;
    struct dwrt_system_db_status system_db_status;

    g_supervisor_mode = 1;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sig_handler;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);

    if (wait_for_persistent_store() != 0)
        return 1;
    if (dwrt_system_db_sync(&system_db_status) != 0) {
        size_t i;

        for (i = 0; i < system_db_status.count; i++) {
            if (system_db_status.items[i].error[0])
                fprintf(stderr,
                        "dreamingwrt-init: system database %s sync failed: %s\n",
                        system_db_status.items[i].name,
                        system_db_status.items[i].error);
        }
        fprintf(stderr,
                "dreamingwrt-init: keeping valid runtime databases where available\n");
        if (system_db_status.conflicts) {
            fprintf(stderr,
                    "dreamingwrt-init: refusing component startup because firmware system database paths conflict\n");
            return 1;
        }
    } else if (system_db_status.changed) {
        fprintf(stderr,
                "dreamingwrt-init: promoted %d firmware system database(s) before component startup\n",
                system_db_status.changed);
    }
    load_config();

    g_listen_fd = setup_socket(sock_path);
    if (g_listen_fd < 0) {
        fprintf(stderr, "dreamingwrt-init: cannot bind %s: %s\n", sock_path, strerror(errno));
        return 1;
    }

    fprintf(stderr, "dreamingwrt-init: supervisor started socket=%s\n", sock_path);
    restore_apply_rc = maybe_apply_armed_config_restore("supervisor_start");
    if (restore_apply_rc == 0) {
        ob_init(&dummy);
        start_all(&dummy, 1);
        ob_free(&dummy);
    }

    while (!g_stop_requested) {
        fd_set rfds;
        struct timeval tv;
        int rc;

        reap_children();
        supervise_components();
        /* /etc/dreamingwrt may be bind-mounted after this supervisor starts. */
        (void)maybe_apply_armed_config_restore("persistent_store_ready");
        maybe_auto_rollback_scan();
        {
            struct outbuf restore_out;
            int restore_rc;

            ob_init(&restore_out);
            {
                struct dwrt_config_restore_hooks restore_hooks;

                config_restore_hooks(&restore_hooks, &restore_out);
                restore_rc = dwrt_config_restore_maybe_rollback(
                    &restore_hooks, (int64_t)time(NULL), &restore_info);
            }
            if (restore_rc > 0) {
                fprintf(stderr,
                        "dreamingwrt-init: config restore auto-rolled back operation=%s reason=%s\n",
                        restore_info.operation_id, restore_info.error);
            } else if (restore_rc < 0) {
                fprintf(stderr,
                        "dreamingwrt-init: config restore auto-rollback failed operation=%s error=%s\n",
                        restore_info.operation_id, restore_info.error);
            }
            ob_free(&restore_out);
        }

        FD_ZERO(&rfds);
        FD_SET(g_listen_fd, &rfds);
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        rc = select(g_listen_fd + 1, &rfds, NULL, NULL, &tv);
        if (rc < 0) {
            if (errno == EINTR)
                continue;
            fprintf(stderr, "dreamingwrt-init: select failed: %s\n", strerror(errno));
            break;
        }
        if (rc > 0 && FD_ISSET(g_listen_fd, &rfds)) {
            int cfd = accept(g_listen_fd, NULL, NULL);
            if (cfd >= 0) {
                set_fd_cloexec(cfd);
                serve_client(cfd);
                close(cfd);
            }
        }
    }

    fprintf(stderr, "dreamingwrt-init: stopping components\n");
    ob_init(&dummy);
    stop_all(&dummy, 1);
    ob_free(&dummy);
    close(g_listen_fd);
    unlink(sock_path);
    return 0;
}

static int connect_socket(const char *sock_path)
{
    int fd;
    struct sockaddr_un addr;

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", sock_path);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int client_send_command(const char *sock_path, int argc, char **argv, int json)
{
    int fd;
    struct outbuf line;
    char buf[1024];
    ssize_t n;
    int i;
    struct outbuf response;
    int command_rc = 0;

    fd = connect_socket(sock_path);
    if (fd < 0)
        return -1;

    ob_init(&line);
    for (i = 0; i < argc; i++)
        ob_appendf(&line, "%s%s", i ? " " : "", argv[i]);
    if (json)
        ob_appendf(&line, " --json");
    ob_appendf(&line, "\n");

    (void)write(fd, line.data, line.len);
    ob_free(&line);

    ob_init(&response);
    while ((n = read(fd, buf, sizeof(buf))) > 0)
        ob_append_mem(&response, buf, (size_t)n);
    close(fd);
    if (response.data && response.len)
        (void)write(STDOUT_FILENO, response.data, response.len);
    if (argc > 0 && !strcmp(argv[0], "check") && json && response.data) {
        if (strstr(response.data, "\"ok\": false"))
            command_rc = 1;
    }
    ob_free(&response);
    return command_rc;
}

static int fallback_readonly(int argc, char **argv, int json)
{
    struct outbuf out;
    const char *cmd = argc > 0 ? argv[0] : "status";
    const char *target = "all";
    int force = 0;
    int no_storage = 0;
    int i;
    int rc = 0;

    g_supervisor_mode = 0;
    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--force")) {
            force = 1;
            continue;
        }
        if (!strcmp(argv[i], "--no-storage")) {
            no_storage = 1;
            continue;
        }
        if (!strcmp(target, "all"))
            target = argv[i];
    }
    ob_init(&out);
    if (strcmp(cmd, "list") == 0) {
        if (json)
            emit_list_json(&out);
        else
            emit_components_plain(&out, "all");
    } else if (strcmp(cmd, "status") == 0) {
        if (strcmp(target, "all") != 0 && !find_component(target)) {
            ob_free(&out);
            return -1;
        }
        if (json)
            emit_components_json(&out, target, !no_storage);
        else {
            emit_components_plain(&out, target);
            emit_storage_plain(&out);
        }
    } else if (strcmp(cmd, "check") == 0) {
        rc = emit_check(&out, json);
    } else if (strcmp(cmd, "rollback-scan") == 0 || strcmp(cmd, "rollback_scan") == 0) {
        struct rollback_scan_result r;

        auto_rollback_scan(&r);
        emit_rollback_scan_result(&out, &r, json);
    } else if (strcmp(cmd, "enable") == 0 || strcmp(cmd, "disable") == 0) {
        if (argc < 2) {
            ob_free(&out);
            return -1;
        }
        set_component_enabled(&out, target, strcmp(cmd, "enable") == 0, force, json);
    } else {
        ob_free(&out);
        return -1;
    }
    if (out.data && out.len)
        fwrite(out.data, 1, out.len, stdout);
    ob_free(&out);
    return rc;
}

int main(int argc, char **argv)
{
    const char *sock_path = DWRT_INIT_SOCKET;
    char *cmd_argv[8];
    int cmd_argc = 0;
    int json = 0;
    int i;

    if (argc <= 1) {
        usage(stdout);
        return 0;
    }

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage(stdout);
            return 0;
        }
        if (strcmp(argv[i], "--version") == 0) {
            printf("dreamingwrt-init %s\n", DWRT_INIT_VERSION);
            return 0;
        }
        if (strcmp(argv[i], "--json") == 0) {
            json = 1;
            continue;
        }
        if (strcmp(argv[i], "--force") == 0) {
            if (cmd_argc < (int)ARRAY_SIZE(cmd_argv))
                cmd_argv[cmd_argc++] = argv[i];
            continue;
        }
        if (strcmp(argv[i], "--no-storage") == 0) {
            if (cmd_argc < (int)ARRAY_SIZE(cmd_argv))
                cmd_argv[cmd_argc++] = argv[i];
            continue;
        }
        if (strcmp(argv[i], "--socket") == 0 && i + 1 < argc) {
            sock_path = argv[++i];
            continue;
        }
        if (cmd_argc < (int)ARRAY_SIZE(cmd_argv))
            cmd_argv[cmd_argc++] = argv[i];
    }

    if (cmd_argc <= 0) {
        usage(stdout);
        return 0;
    }

    g_socket_path = sock_path;

    if (strcmp(cmd_argv[0], "run") == 0)
        return run_supervisor(sock_path);

    load_config();

    {
        int command_rc = client_send_command(sock_path, cmd_argc, cmd_argv, json);
        if (command_rc >= 0)
            return command_rc;
    }

    if (fallback_readonly(cmd_argc, cmd_argv, json) == 0)
        return 0;

    fprintf(stderr,
            "dreamingwrt-init: supervisor is not running at %s; start it with /etc/init.d/dreamingwrt-init start or 'dreamingwrt-init run'\n",
            sock_path);
    return 1;
}
