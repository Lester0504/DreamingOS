// SPDX-License-Identifier: GPL-2.0-or-later
#include "logd_internal.h"

#include <dirent.h>
#include <fcntl.h>
#include <sys/statvfs.h>
#include <sys/wait.h>

struct logd_port_state {
    char ifname[32];
    int known;
    int seen;
    int carrier;
    int speed;
    char operstate[32];
    char duplex[32];
};

struct logd_dhcp_lease {
    int64_t expires;
    char mac[32];
    char ip[64];
    char hostname[128];
    char client_id[128];
};

static struct uloop_timeout g_collect_timer;
static const char *logd_line_severity(const char *line);

static struct logd_collector_runtime g_collectors[] = {
    { .name = "system_log" },
    { .name = "kernel_log" },
    { .name = "resource" },
    { .name = "port" },
    { .name = "dhcp_lease" },
};

static struct logd_port_state g_ports[LOGD_MAX_PORTS];
static uint64_t g_cpu_last_total;
static uint64_t g_cpu_last_idle;
static int g_cpu_sample_valid;

static struct logd_collector_runtime *logd_collector_runtime_find(const char *name)
{
    size_t i;

    if (!name || !name[0])
        return NULL;
    for (i = 0; i < ARRAY_SIZE(g_collectors); i++) {
        if (!strcmp(g_collectors[i].name, name))
            return &g_collectors[i];
    }
    return NULL;
}

static int logd_collector_name_ok(const char *name)
{
    return logd_collector_runtime_find(name) != NULL;
}

static void logd_collector_config_default(const char *name, struct logd_collector_config *cfg)
{
    if (!cfg)
        return;
    cfg->enabled = 1;
    cfg->interval_s = 30;
    cfg->cooldown_s = 60;
    snprintf(cfg->options_json, sizeof(cfg->options_json), "%s", "{}");
    if (name && !strcmp(name, "port")) {
        cfg->interval_s = 5;
        cfg->cooldown_s = 30;
    } else if (name && !strcmp(name, "system_log")) {
        cfg->interval_s = 15;
    } else if (name && !strcmp(name, "kernel_log")) {
        cfg->interval_s = 15;
    } else if (name && !strcmp(name, "resource")) {
        cfg->interval_s = 30;
        cfg->cooldown_s = 300;
        snprintf(cfg->options_json, sizeof(cfg->options_json),
                 "%s", "{\"cpu_warn\":85,\"cpu_critical\":95,\"mem_warn\":85,\"mem_critical\":95,\"disk_warn\":90,\"disk_critical\":97,\"inode_warn\":90,\"inode_critical\":97,\"temp_warn\":80,\"temp_critical\":90}");
    } else if (name && !strcmp(name, "dhcp_lease")) {
        cfg->interval_s = 15;
        cfg->cooldown_s = 0;
    }
}

static int logd_collector_config_load(const char *name, struct logd_collector_config *cfg)
{
    sqlite3_stmt *st;
    const char *s;
    int rc;

    if (!name || !cfg)
        return -1;
    logd_collector_config_default(name, cfg);
    st = logd_config_prepare("SELECT enabled,interval_s,cooldown_s,options_json FROM logd_collector_settings WHERE name=?1");
    if (!st)
        return -1;
    sqlite3_bind_text(st, 1, name, -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) {
        cfg->enabled = sqlite3_column_int(st, 0) ? 1 : 0;
        cfg->interval_s = sqlite3_column_int(st, 1);
        cfg->cooldown_s = sqlite3_column_int(st, 2);
        s = (const char *)sqlite3_column_text(st, 3);
        snprintf(cfg->options_json, sizeof(cfg->options_json), "%s", s && s[0] ? s : "{}");
    } else if (rc != SQLITE_DONE) {
        sqlite3_finalize(st);
        return -1;
    }
    sqlite3_finalize(st);
    if (cfg->interval_s < 2) cfg->interval_s = 2;
    if (cfg->interval_s > 86400) cfg->interval_s = 86400;
    if (cfg->cooldown_s < 0) cfg->cooldown_s = 0;
    if (cfg->cooldown_s > 86400) cfg->cooldown_s = 86400;
    return 0;
}

static int logd_cooldown_allow(const char *collector, const char *key, int cooldown_s)
{
    char state_key[160];
    char buf[64];
    int64_t now = logd_now_s();
    int64_t last = 0;

    if (!collector || !key || cooldown_s <= 0)
        return 1;
    snprintf(state_key, sizeof(state_key), "cooldown:%s", key);
    if (logd_collector_state_get(collector, state_key, buf, sizeof(buf), "0") == 0)
        last = atoll(buf);
    if (last > 0 && now - last < cooldown_s)
        return 0;
    return 1;
}

struct logd_parsed_log_line {
    int ok;
    int explicit_year;
    int64_t ts;
    char facility[32];
    char facility_level[32];
    char host[128];
    char module[128];
    char message[LOGD_MAX_LOG_LINE];
};

struct logd_program_package {
    char program[128];
    char package[128];
};

#define LOGD_MAX_PROGRAM_PACKAGES 512
static struct logd_program_package g_program_packages[LOGD_MAX_PROGRAM_PACKAGES];
static size_t g_program_package_count;
static int g_program_packages_loaded;

static int logd_month_index(const char *s)
{
    static const char *months[] = {
        "Jan", "Feb", "Mar", "Apr", "May", "Jun",
        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    };
    size_t i;

    if (!s || !s[0])
        return -1;
    for (i = 0; i < ARRAY_SIZE(months); i++) {
        if (!strncasecmp(s, months[i], 3))
            return (int)i;
    }
    return -1;
}

static int logd_facility_token(const char *s, size_t len)
{
    size_t i;
    int dot = 0;

    if (!s || len == 0 || len >= 32)
        return 0;
    for (i = 0; i < len; i++) {
        unsigned char c = (unsigned char)s[i];

        if (c == '.') {
            dot = 1;
            continue;
        }
        if (!isalnum(c) && c != '_' && c != '-')
            return 0;
    }
    return dot;
}

static void logd_copy_trim(char *out, size_t out_len, const char *s, size_t len)
{
    if (!out || out_len == 0)
        return;
    out[0] = 0;
    if (!s)
        return;
    while (len > 0 && isspace((unsigned char)*s)) {
        s++;
        len--;
    }
    while (len > 0 && isspace((unsigned char)s[len - 1]))
        len--;
    if (len >= out_len)
        len = out_len - 1;
    memcpy(out, s, len);
    out[len] = 0;
}

static void logd_parse_log_body(const char *rest, struct logd_parsed_log_line *parsed)
{
    const char *p = rest;
    const char *space;
    const char *colon;
    size_t len;

    if (!p || !parsed)
        return;
    while (*p == ' ')
        p++;
    space = strchr(p, ' ');
    if (space && logd_facility_token(p, (size_t)(space - p))) {
        logd_copy_trim(parsed->facility, sizeof(parsed->facility), p, (size_t)(space - p));
        {
            char *dot = strchr(parsed->facility, '.');

            if (dot) {
                snprintf(parsed->facility_level, sizeof(parsed->facility_level), "%s", dot + 1);
                *dot = 0;
            }
        }
        p = space + 1;
        while (*p == ' ')
            p++;
    }

    colon = strchr(p, ':');
    if (!colon) {
        logd_copy_trim(parsed->message, sizeof(parsed->message), p, strlen(p));
        return;
    }

    len = (size_t)(colon - p);
    if (!parsed->facility[0]) {
        const char *first_space = memchr(p, ' ', len);

        if (first_space && first_space + 1 < colon) {
            logd_copy_trim(parsed->host, sizeof(parsed->host), p, (size_t)(first_space - p));
            while (first_space + 1 < colon && first_space[1] == ' ')
                first_space++;
            logd_copy_trim(parsed->module, sizeof(parsed->module),
                           first_space + 1, (size_t)(colon - first_space - 1));
        } else {
            logd_copy_trim(parsed->module, sizeof(parsed->module), p, len);
        }
    } else {
        logd_copy_trim(parsed->module, sizeof(parsed->module), p, len);
    }
    p = colon + 1;
    while (*p == ' ')
        p++;
    logd_copy_trim(parsed->message, sizeof(parsed->message), p, strlen(p));
}

static void logd_program_normalize(const char *module, char *out, size_t out_len)
{
    const char *base = module ? module : "";
    size_t n = 0;

    if (!out || out_len == 0)
        return;
    out[0] = 0;
    if (strrchr(base, '/'))
        base = strrchr(base, '/') + 1;
    while (*base && n + 1 < out_len) {
        unsigned char c = (unsigned char)*base++;

        if (c == '[' || c == '(' || c == ':' || isspace(c))
            break;
        if (isalnum(c) || c == '_' || c == '-' || c == '.')
            out[n++] = (char)tolower(c);
    }
    out[n] = 0;
}

static void logd_program_package_add(const char *program, const char *package)
{
    size_t i;

    if (!program || !program[0] || !package || !package[0])
        return;
    for (i = 0; i < g_program_package_count; i++) {
        if (!strcmp(g_program_packages[i].program, program))
            return;
    }
    if (g_program_package_count >= ARRAY_SIZE(g_program_packages))
        return;
    snprintf(g_program_packages[g_program_package_count].program,
             sizeof(g_program_packages[g_program_package_count].program), "%s", program);
    snprintf(g_program_packages[g_program_package_count].package,
             sizeof(g_program_packages[g_program_package_count].package), "%s", package);
    g_program_package_count++;
}

/* Returns 0 for non-executable folders, 1 for standard executable roots, and
 * 2 for usr/lib (only extension-less helper binaries such as OpenSSH's
 * sshd-session/sshd-auth/sftp-server, never the many shared objects). */
static int logd_apk_exec_folder(const char *folder)
{
    static const char *roots[] = {
        "usr/bin", "usr/sbin", "bin", "sbin", "etc/init.d",
    };
    size_t i;

    if (!folder)
        return 0;
    for (i = 0; i < ARRAY_SIZE(roots); i++)
        if (!strcmp(folder, roots[i]))
            return 1;
    if (!strcmp(folder, "usr/lib"))
        return 2;
    return 0;
}

static void logd_program_packages_load_apk(void)
{
    /* glibc builds ship apk instead of opkg; its installed database lists a
     * package's files as an 'F:<dir>' folder context followed by 'R:<file>'
     * entries. Reconstruct program -> package ownership from that layout so
     * log events keep a 'package' field after the apk migration. */
    FILE *fp;
    char line[512];
    char package[128];
    char folder[256];
    int folder_is_exec;

    fp = fopen("/lib/apk/db/installed", "r");
    if (!fp)
        return;
    package[0] = 0;
    folder[0] = 0;
    folder_is_exec = 0;
    while (fgets(line, sizeof(line), fp)) {
        char *nl = strpbrk(line, "\r\n");
        char program[128];

        if (nl)
            *nl = 0;
        if (line[0] == 0 || line[1] != ':')
            continue;
        switch (line[0]) {
        case 'P':
            logd_copy_trim(package, sizeof(package), line + 2, strlen(line + 2));
            folder[0] = 0;
            folder_is_exec = 0;
            break;
        case 'F':
            logd_copy_trim(folder, sizeof(folder), line + 2, strlen(line + 2));
            folder_is_exec = logd_apk_exec_folder(folder);
            break;
        case 'R':
            if (!folder_is_exec || !package[0])
                break;
            /* usr/lib mostly holds shared objects; only register bare helper
             * binaries (no filename extension) so libraries never crowd out
             * real program tags in the fixed-size ownership table. */
            if (folder_is_exec == 2 && strchr(line + 2, '.'))
                break;
            logd_program_normalize(line + 2, program, sizeof(program));
            logd_program_package_add(program, package);
            break;
        default:
            break;
        }
    }
    fclose(fp);
}

static void logd_program_packages_load_opkg(void)
{
    DIR *dir;
    struct dirent *de;

    dir = opendir("/usr/lib/opkg/info");
    if (!dir)
        return;
    while ((de = readdir(dir)) != NULL) {
        const char *suffix = strstr(de->d_name, ".list");
        char path[256];
        char package[128];
        char line[512];
        FILE *fp;

        if (!suffix || suffix[5] != 0 || suffix == de->d_name)
            continue;
        logd_copy_trim(package, sizeof(package), de->d_name, (size_t)(suffix - de->d_name));
        if (snprintf(path, sizeof(path), "/usr/lib/opkg/info/%s", de->d_name) >=
            (int)sizeof(path))
            continue;
        fp = fopen(path, "r");
        if (!fp)
            continue;
        while (fgets(line, sizeof(line), fp)) {
            char *nl = strpbrk(line, "\r\n");
            const char *base;
            char program[128];

            if (nl)
                *nl = 0;
            if (strncmp(line, "/usr/bin/", 9) && strncmp(line, "/usr/sbin/", 10) &&
                strncmp(line, "/bin/", 5) && strncmp(line, "/sbin/", 6) &&
                strncmp(line, "/etc/init.d/", 12))
                continue;
            base = strrchr(line, '/');
            logd_program_normalize(base ? base + 1 : line, program, sizeof(program));
            logd_program_package_add(program, package);
        }
        fclose(fp);
    }
    closedir(dir);
}

static void logd_program_packages_load(void)
{
    if (g_program_packages_loaded)
        return;
    g_program_packages_loaded = 1;
    /* opkg (musl builds) and apk (glibc builds) never coexist in practice;
     * probe both so a single logd binary keeps package ownership regardless of
     * which package manager the running firmware shipped. logd_program_package_add
     * keeps the first mapping per program, so opkg wins on the rare overlap. */
    logd_program_packages_load_opkg();
    logd_program_packages_load_apk();
}

static const char *logd_program_package(const char *program)
{
    size_t i;

    logd_program_packages_load();
    for (i = 0; i < g_program_package_count; i++) {
        if (!strcmp(g_program_packages[i].program, program))
            return g_program_packages[i].package;
    }
    return "";
}

static const char *logd_program_label(const char *program)
{
    static const struct { const char *id; const char *label; } labels[] = {
        { "kernel", "Kernel" }, { "procd", "procd" }, { "netifd", "netifd" },
        { "dnsmasq", "dnsmasq" }, { "odhcpd", "odhcpd" }, { "dropbear", "Dropbear" },
        { "sshd", "OpenSSH" }, { "openclash", "OpenClash" }, { "mihomo", "Mihomo" },
        { "mosdns", "MosDNS" }, { "homeproxy", "HomeProxy" }, { "tailscaled", "Tailscale" },
        { "dockerd", "Docker" },
    };
    size_t i;

    for (i = 0; i < ARRAY_SIZE(labels); i++) {
        if (!strcmp(program, labels[i].id))
            return labels[i].label;
    }
    return program && program[0] ? program : "System";
}

static const char *logd_source_label(const char *source_id)
{
    if (!strcmp(source_id, "kernel")) return "Kernel logs";
    if (!strcmp(source_id, "audit")) return "Audit logs";
    if (!strcmp(source_id, "notification")) return "Notifications";
    if (!strcmp(source_id, "alarm")) return "Alarms";
    if (!strcmp(source_id, "syslog")) return "Remote syslog";
    return "General logs";
}

static const char *logd_facility_severity(const char *level, const char *line)
{
    if (level && level[0]) {
        if (!strcasecmp(level, "emerg") || !strcasecmp(level, "alert") ||
            !strcasecmp(level, "crit")) return "critical";
        if (!strcasecmp(level, "err") || !strcasecmp(level, "error")) return "error";
        if (!strcasecmp(level, "warn") || !strcasecmp(level, "warning")) return "warning";
        if (!strcasecmp(level, "notice")) return "notice";
        if (!strcasecmp(level, "info") || !strcasecmp(level, "debug")) return "info";
    }
    return logd_line_severity(line);
}

static void logd_strip_kernel_clock(const char *message, char *out, size_t out_len,
                                    char *clock_key, size_t clock_key_len)
{
    const char *p = message ? message : "";
    const char *end;

    if (clock_key && clock_key_len)
        clock_key[0] = 0;
    while (*p == ' ')
        p++;
    if (*p == '[' && (end = strchr(p, ']')) != NULL) {
        int valid = 1;
        const char *q;

        for (q = p + 1; q < end; q++) {
            if (!isdigit((unsigned char)*q) && *q != '.' && *q != ' ') {
                valid = 0;
                break;
            }
        }
        if (valid) {
            if (clock_key && clock_key_len)
                logd_copy_trim(clock_key, clock_key_len, p + 1, (size_t)(end - p - 1));
            p = end + 1;
            while (*p == ' ')
                p++;
        }
    }
    snprintf(out, out_len, "%s", p);
}

static int64_t logd_make_log_ts(int mon, int mday, int hour, int min, int sec,
                                int year, int explicit_year)
{
    time_t now = time(NULL);
    struct tm tm_now;
    struct tm tm_log;
    time_t out;

    localtime_r(&now, &tm_now);
    if (year <= 0)
        year = tm_now.tm_year + 1900;
    memset(&tm_log, 0, sizeof(tm_log));
    tm_log.tm_year = year - 1900;
    tm_log.tm_mon = mon;
    tm_log.tm_mday = mday;
    tm_log.tm_hour = hour;
    tm_log.tm_min = min;
    tm_log.tm_sec = sec;
    tm_log.tm_isdst = -1;
    out = mktime(&tm_log);
    if (out == (time_t)-1)
        return 0;
    if (!explicit_year && out > now + 86400) {
        tm_log.tm_year--;
        out = mktime(&tm_log);
        if (out == (time_t)-1)
            return 0;
    }
    return (int64_t)out;
}

static int logd_parse_logread_line(const char *line, struct logd_parsed_log_line *parsed)
{
    char dow[8];
    char mon_s[8];
    int mon;
    int day;
    int hour;
    int min;
    int sec;
    int year;
    int off = 0;
    int rc;

    if (!parsed)
        return 0;
    memset(parsed, 0, sizeof(*parsed));
    if (!line || !line[0])
        return 0;

    rc = sscanf(line, "%7s %7s %d %d:%d:%d %d %n",
                dow, mon_s, &day, &hour, &min, &sec, &year, &off);
    mon = logd_month_index(mon_s);
    if (rc == 7 && mon >= 0 && off > 0) {
        parsed->ts = logd_make_log_ts(mon, day, hour, min, sec, year, 1);
        parsed->explicit_year = 1;
        parsed->ok = parsed->ts > 0;
        logd_parse_log_body(line + off, parsed);
        return parsed->ok;
    }

    off = 0;
    rc = sscanf(line, "%7s %d %d:%d:%d %d %n",
                mon_s, &day, &hour, &min, &sec, &year, &off);
    mon = logd_month_index(mon_s);
    if (rc == 6 && mon >= 0 && off > 0) {
        parsed->ts = logd_make_log_ts(mon, day, hour, min, sec, year, 1);
        parsed->explicit_year = 1;
        parsed->ok = parsed->ts > 0;
        logd_parse_log_body(line + off, parsed);
        return parsed->ok;
    }

    off = 0;
    rc = sscanf(line, "%7s %d %d:%d:%d %n",
                mon_s, &day, &hour, &min, &sec, &off);
    mon = logd_month_index(mon_s);
    if (rc == 5 && mon >= 0 && off > 0) {
        parsed->ts = logd_make_log_ts(mon, day, hour, min, sec, 0, 0);
        parsed->ok = parsed->ts > 0;
        logd_parse_log_body(line + off, parsed);
        return parsed->ok;
    }
    return 0;
}

static void logd_normalize_log_line(const char *line, char *out, size_t out_len)
{
    const char *p = line ? line : "";
    size_t n = 0;
    int token = 0;

    if (!out || out_len == 0)
        return;
    out[0] = '\0';

    /* OpenWrt logread prefixes every row with wall-clock time. It must not be
     * part of dedupe, or every minute of the same failure becomes a new event. */
    if (isalpha((unsigned char)p[0]) && isalpha((unsigned char)p[1]) &&
        isalpha((unsigned char)p[2]) && p[3] == ' ') {
        const char *q = p;
        while (*q && token < 5) {
            while (*q == ' ')
                q++;
            if (!*q)
                break;
            while (*q && *q != ' ')
                q++;
            token++;
        }
        while (*q == ' ')
            q++;
        if (token == 5 && *q)
            p = q;
    }

    while (*p && n + 1 < out_len) {
        if (*p == '(') {
            const char *q = p + 1;
            while (isdigit((unsigned char)*q))
                q++;
            if (q > p + 1 && *q == ')') {
                if (n + 3 >= out_len)
                    break;
                out[n++] = '(';
                out[n++] = '#';
                out[n++] = ')';
                p = q + 1;
                continue;
            }
        }
        if (*p == '[') {
            const char *q = p + 1;
            while (*q == ' ' || isdigit((unsigned char)*q) || *q == '.')
                q++;
            if (q > p + 1 && *q == ']') {
                if (n + 3 >= out_len)
                    break;
                out[n++] = '[';
                out[n++] = '#';
                out[n++] = ']';
                p = q + 1;
                continue;
            }
        }
        out[n++] = (char)tolower((unsigned char)*p++);
    }
    out[n] = '\0';
}

static void logd_normalize_callbacks_suppressed(char *line)
{
    char *phrase;
    char *end;
    char *start;

    if (!line || !line[0])
        return;
    phrase = strstr(line, " callbacks suppressed");
    if (!phrase)
        return;
    end = phrase;
    while (end > line && isspace((unsigned char)end[-1]))
        end--;
    start = end;
    while (start > line && isdigit((unsigned char)start[-1]))
        start--;
    if (start == end)
        return;
    *start++ = '#';
    memmove(start, end, strlen(end) + 1);
}

static void logd_cooldown_mark(const char *collector, const char *key, int cooldown_s)
{
    char state_key[160];
    char buf[64];
    int64_t now = logd_now_s();

    if (!collector || !key || cooldown_s <= 0)
        return;
    snprintf(buf, sizeof(buf), "%lld", (long long)now);
    snprintf(state_key, sizeof(state_key), "cooldown:%s", key);
    logd_collector_state_set(collector, state_key, buf);
}

static const char *logd_line_severity(const char *line)
{
    if (logd_contains_ci(line, "panic") || logd_contains_ci(line, "fatal") ||
        logd_contains_ci(line, "oom") || logd_contains_ci(line, "segfault"))
        return "critical";
    if (logd_contains_ci(line, " error") || logd_contains_ci(line, " err") ||
        logd_contains_ci(line, "failed") || logd_contains_ci(line, "failure"))
        return "error";
    if (logd_contains_ci(line, "warn"))
        return "warning";
    if (logd_contains_ci(line, "notice"))
        return "notice";
    return "info";
}

static void logd_line_classify(const char *line, int kernel, const char **category, const char **event)
{
    *category = kernel ? "kernel" : "system";
    *event = "log_line";
    if (kernel && logd_contains_ci(line, "callbacks suppressed")) {
        *event = "callbacks_suppressed";
        return;
    }
    if (logd_contains_ci(line, "pppoe") || logd_contains_ci(line, "pppd")) {
        *category = "pppoe";
        *event = "pppoe_log";
    } else if (logd_contains_ci(line, "dhcp") || logd_contains_ci(line, "dnsmasq") ||
               logd_contains_ci(line, "odhcpd") || logd_contains_ci(line, "udhcpc")) {
        *category = "dhcp";
        *event = "dhcp_log";
    } else if (logd_contains_ci(line, "netifd") || logd_contains_ci(line, " wan") ||
               logd_contains_ci(line, "interface 'wan'")) {
        *category = "wan";
        *event = "wan_log";
    } else if (logd_contains_ci(line, "link is up") || logd_contains_ci(line, "link is down") ||
               logd_contains_ci(line, "carrier")) {
        *category = "port";
        *event = "port_log";
    } else if (logd_contains_ci(line, "auth") || logd_contains_ci(line, "login") ||
               logd_contains_ci(line, "dropbear") || logd_contains_ci(line, "sshd") ||
               logd_contains_ci(line, "sudo")) {
        /*
         * Daemon authentication text (dropbear/sshd/sudo/nginx login lines) is
         * device-side SECURITY logging, not the admin operation audit ledger.
         *
         * This branch used to set category="audit"/event="auth_log", which the
         * classifier then promoted to ADMIN_AUTH_EVENT and the log center showed
         * under AUDIT. That let an nginx 404 or a dropbear probe masquerade as an
         * administrator action inferred purely from the substring "login". The
         * real admin operation audit is written by webd with an explicit
         * web_audit flag; a raw log line is never that. Route these to SECURITY
         * with a non-admin event name so they stay searchable but out of the
         * ledger.
         */
        *category = "security";
        *event = "security_auth_log";
    }
}

static int logd_publish_log_line(const char *name, const char *line, int kernel,
                                 const char *reader,
                                 int cooldown_s, int cursor_recovered)
{
    const char *category;
    const char *event;
    const char *severity;
    struct json_object *detail;
    char hash[32];
    char normalized[LOGD_MAX_LOG_LINE];
    char canonical_message[LOGD_MAX_LOG_LINE];
    char fingerprint_input[LOGD_MAX_LOG_LINE + 256];
    char program[128];
    char clock_key[64];
    char title[192];
    char dedupe[320];
    struct logd_parsed_log_line parsed;
    struct json_object *body;
    struct json_object *resp;
    int ok;

    if (!name || !line || !line[0])
        return 0;
    logd_parse_logread_line(line, &parsed);
    kernel = kernel || !strcasecmp(parsed.facility, "kern") ||
             !strcasecmp(parsed.module, "kernel");
    logd_strip_kernel_clock(parsed.ok && parsed.message[0] ? parsed.message : line,
                            canonical_message, sizeof(canonical_message),
                            clock_key, sizeof(clock_key));
    logd_normalize_log_line(canonical_message, normalized, sizeof(normalized));
    logd_normalize_callbacks_suppressed(normalized);
    logd_program_normalize(kernel ? "kernel" : parsed.module, program, sizeof(program));
    if (!program[0])
        snprintf(program, sizeof(program), "%s", kernel ? "kernel" : "system");
    logd_line_classify(canonical_message, kernel, &category, &event);
    severity = logd_facility_severity(parsed.facility_level, canonical_message);
    snprintf(fingerprint_input, sizeof(fingerprint_input), "%s|%s|%s",
             kernel ? "kernel" : (!strcmp(category, "audit") ? "audit" : "general"),
             program, normalized);
    logd_hash_hex(fingerprint_input, hash, sizeof(hash));
    snprintf(dedupe, sizeof(dedupe), "log:%s", hash);
    if (!logd_cooldown_allow(name, dedupe, cooldown_s))
        return 0;
    logd_title_from_line(canonical_message, title, sizeof(title));
    detail = json_object_new_object();
    if (detail) {
        struct json_object *collectors = json_object_new_array();
        const char *source_id = kernel ? "kernel" : (!strcmp(category, "audit") ? "audit" : "general");
        const char *package = logd_program_package(program);

        json_object_object_add(detail, "line", json_object_new_string(line));
        json_object_object_add(detail, "raw", json_object_new_string(line));
        json_object_object_add(detail, "normalized", json_object_new_string(normalized));
        json_object_object_add(detail, "kernel", json_object_new_boolean(kernel));
        json_object_object_add(detail, "collector", json_object_new_string(name));
        json_object_array_add(collectors, json_object_new_string(name));
        json_object_object_add(detail, "collectors", collectors);
        json_object_object_add(detail, "reader", json_object_new_string(reader ? reader : ""));
        json_object_object_add(detail, "source_id", json_object_new_string(source_id));
        json_object_object_add(detail, "source_label", json_object_new_string(logd_source_label(source_id)));
        json_object_object_add(detail, "program", json_object_new_string(program));
        json_object_object_add(detail, "program_label", json_object_new_string(logd_program_label(program)));
        json_object_object_add(detail, "package", json_object_new_string(package));
        json_object_object_add(detail, "message", json_object_new_string(canonical_message));
        json_object_object_add(detail, "event_fingerprint", json_object_new_string(dedupe + 4));
        if (clock_key[0])
            json_object_object_add(detail, "kernel_clock", json_object_new_string(clock_key));
        if (parsed.ok) {
            json_object_object_add(detail, "timestamp", json_object_new_int64(parsed.ts * 1000));
            json_object_object_add(detail, "original_ts", json_object_new_int64(parsed.ts));
            json_object_object_add(detail, "original_timestamp", json_object_new_int64(parsed.ts * 1000));
            json_object_object_add(detail, "original_timestamp_ms", json_object_new_int64(parsed.ts * 1000));
            json_object_object_add(detail, "timestamp_source", json_object_new_string("logread"));
            if (parsed.explicit_year)
                json_object_object_add(detail, "timestamp_has_year", json_object_new_boolean(1));
            if (parsed.facility[0])
                json_object_object_add(detail, "facility", json_object_new_string(parsed.facility));
            if (parsed.facility_level[0])
                json_object_object_add(detail, "facility_level", json_object_new_string(parsed.facility_level));
            if (parsed.host[0])
                json_object_object_add(detail, "host", json_object_new_string(parsed.host));
            if (parsed.module[0] && !kernel)
                json_object_object_add(detail, "module", json_object_new_string(parsed.module));
        }
        if (cursor_recovered)
            json_object_object_add(detail, "cursor_recovered", json_object_new_boolean(1));
    }
    body = json_object_new_object();
    if (!body) {
        if (detail)
            json_object_put(detail);
        return 0;
    }
    json_object_object_add(body, "severity", json_object_new_string(severity ? severity : "info"));
    json_object_object_add(body, "category", json_object_new_string(category ? category : "system"));
    json_object_object_add(body, "event", json_object_new_string(event ? event : "event"));
    json_object_object_add(body, "source", json_object_new_string(kernel ? "kernel" : (!strcmp(category, "audit") ? "audit" : "general")));
    json_object_object_add(body, "iface", json_object_new_string(""));
    json_object_object_add(body, "title", json_object_new_string(title));
    json_object_object_add(body, "dedupe_key", json_object_new_string(dedupe));
    if (parsed.ok)
        json_object_object_add(body, "ts", json_object_new_int64(parsed.ts));
    if (detail)
        json_object_object_add(body, "detail_json", json_object_get(detail));
    resp = logd_add_event(body);
    ok = resp && logd_json_bool(resp, "ok", 0);
    if (resp)
        json_object_put(resp);
    json_object_put(body);
    if (ok)
        logd_cooldown_mark(name, dedupe, cooldown_s);
    if (detail)
        json_object_put(detail);
    return ok ? 1 : 0;
}

static FILE *logd_open_reader(int kernel, pid_t *pid_out)
{
    int pipefd[2];
    pid_t pid;

    if (pid_out)
        *pid_out = -1;
    if (pipe(pipefd) != 0)
        return NULL;

    pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return NULL;
    }
    if (pid == 0) {
        int devnull;

        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        if (pipefd[1] != STDOUT_FILENO)
            close(pipefd[1]);
        devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, STDERR_FILENO);
            close(devnull);
        }
        if (kernel)
            execlp("dmesg", "dmesg", (char *)NULL);
        else
            execlp("logread", "logread", (char *)NULL);
        _exit(127);
    }

    close(pipefd[1]);
    if (pid_out)
        *pid_out = pid;
    return fdopen(pipefd[0], "r");
}

static int logd_close_reader(FILE *fp, pid_t pid)
{
    int status;

    if (fp)
        fclose(fp);
    if (pid <= 0)
        return -1;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno == EINTR)
            continue;
        return -1;
    }
    if (!WIFEXITED(status))
        return -1;
    return WEXITSTATUS(status);
}

static int logd_collect_logread(const char *name, int kernel, int cooldown_s)
{
    const char *reader = kernel ? "dmesg" : "logread";
    char line[LOGD_MAX_LOG_LINE];
    char last_hash[32];
    char current_hash[32] = "";
    char state_key[64];
    char fallback[LOGD_LOGREAD_FALLBACK_LINES][LOGD_MAX_LOG_LINE];
    FILE *fp;
    pid_t reader_pid = -1;
    int seen_cursor = 0;
    int have_cursor = 0;
    int imported = 0;
    int saw_any = 0;
    int fallback_count = 0;
    int fallback_next = 0;
    int close_rc;
    int state_rc;
    int i;

    snprintf(state_key, sizeof(state_key), "%s", kernel ? "last_hash_kernel" : "last_hash_system");
    memset(fallback, 0, sizeof(fallback));
    state_rc = logd_collector_state_get(name, state_key, last_hash, sizeof(last_hash), "");
    if (state_rc < 0)
        return -1;
    if (state_rc == 0 && last_hash[0])
        have_cursor = 1;
    fp = logd_open_reader(kernel, &reader_pid);
    if (!fp)
        return -1;
    while (fgets(line, sizeof(line), fp)) {
        char *nl;

        nl = strpbrk(line, "\r\n");
        if (nl)
            *nl = 0;
        logd_sanitize_line(line);
        if (!line[0])
            continue;
        saw_any = 1;
        logd_hash_hex(line, current_hash, sizeof(current_hash));
        if (have_cursor && !seen_cursor) {
            snprintf(fallback[fallback_next], sizeof(fallback[0]), "%s", line);
            fallback_next = (fallback_next + 1) % LOGD_LOGREAD_FALLBACK_LINES;
            if (fallback_count < LOGD_LOGREAD_FALLBACK_LINES)
                fallback_count++;
        }
        if (have_cursor && !seen_cursor) {
            if (!strcmp(current_hash, last_hash))
                seen_cursor = 1;
            continue;
        }
        if (!have_cursor)
            continue;
        imported += logd_publish_log_line(name, line, kernel, reader, cooldown_s, 0);
    }
    close_rc = logd_close_reader(fp, reader_pid);
    if (close_rc != 0)
        return -1;
    if (have_cursor && !seen_cursor && fallback_count > 0) {
        int start = (fallback_next + LOGD_LOGREAD_FALLBACK_LINES - fallback_count) % LOGD_LOGREAD_FALLBACK_LINES;

        for (i = 0; i < fallback_count; i++) {
            const char *saved = fallback[(start + i) % LOGD_LOGREAD_FALLBACK_LINES];

            if (!saved[0])
                continue;
            imported += logd_publish_log_line(name, saved, kernel, reader, cooldown_s, 1);
        }
    }
    if (saw_any && current_hash[0] && logd_collector_state_set(name, state_key, current_hash) != 0)
        return -1;
    return imported;
}

static int logd_read_cpu_percent(double *pct)
{
    FILE *fp;
    char label[16];
    uint64_t user = 0, nice = 0, system = 0, idle = 0, iowait = 0, irq = 0, softirq = 0, steal = 0;
    uint64_t idle_all, non_idle, total, totald, idled;

    if (!pct)
        return -1;
    fp = fopen("/proc/stat", "r");
    if (!fp)
        return -1;
    if (fscanf(fp, "%15s %" SCNu64 " %" SCNu64 " %" SCNu64 " %" SCNu64 " %" SCNu64 " %" SCNu64 " %" SCNu64 " %" SCNu64,
               label, &user, &nice, &system, &idle, &iowait, &irq, &softirq, &steal) < 5) {
        fclose(fp);
        return -1;
    }
    fclose(fp);
    idle_all = idle + iowait;
    non_idle = user + nice + system + irq + softirq + steal;
    total = idle_all + non_idle;
    if (!g_cpu_sample_valid || total <= g_cpu_last_total) {
        g_cpu_last_total = total;
        g_cpu_last_idle = idle_all;
        g_cpu_sample_valid = 1;
        *pct = 0.0;
        return 1;
    }
    totald = total - g_cpu_last_total;
    idled = idle_all - g_cpu_last_idle;
    g_cpu_last_total = total;
    g_cpu_last_idle = idle_all;
    if (totald == 0)
        return -1;
    *pct = (double)(totald - idled) * 100.0 / (double)totald;
    if (*pct < 0.0) *pct = 0.0;
    if (*pct > 100.0) *pct = 100.0;
    return 0;
}

static int logd_read_mem_percent(double *pct, uint64_t *total_kb, uint64_t *avail_kb)
{
    FILE *fp;
    char line[160];
    char key[64];
    uint64_t value;
    uint64_t total = 0;
    uint64_t avail = 0;
    uint64_t free_kb = 0;
    uint64_t buffers = 0;
    uint64_t cached = 0;

    if (!pct)
        return -1;
    fp = fopen("/proc/meminfo", "r");
    if (!fp)
        return -1;
    while (fgets(line, sizeof(line), fp)) {
        if (sscanf(line, "%63s %" SCNu64, key, &value) != 2)
            continue;
        if (!strcmp(key, "MemTotal:")) total = value;
        else if (!strcmp(key, "MemAvailable:")) avail = value;
        else if (!strcmp(key, "MemFree:")) free_kb = value;
        else if (!strcmp(key, "Buffers:")) buffers = value;
        else if (!strcmp(key, "Cached:")) cached = value;
    }
    fclose(fp);
    if (!avail)
        avail = free_kb + buffers + cached;
    if (!total)
        return -1;
    *pct = (double)(total - avail) * 100.0 / (double)total;
    if (total_kb) *total_kb = total;
    if (avail_kb) *avail_kb = avail;
    return 0;
}

static int logd_disk_percent(const char *path, double *disk_pct, double *inode_pct)
{
    struct statvfs st;

    if (!path || !disk_pct || !inode_pct || statvfs(path, &st) != 0)
        return -1;
    if (st.f_blocks > 0)
        *disk_pct = (double)(st.f_blocks - st.f_bavail) * 100.0 / (double)st.f_blocks;
    else
        *disk_pct = 0.0;
    if (st.f_files > 0)
        *inode_pct = (double)(st.f_files - st.f_favail) * 100.0 / (double)st.f_files;
    else
        *inode_pct = 0.0;
    return 0;
}

static void logd_collect_resource_one(const char *metric, double value, int warn, int critical,
                                      int cooldown_s, struct json_object *detail)
{
    const char *severity = NULL;
    char title[160];
    char dedupe[160];
    char cooldown_key[192];
    char active_key[160];
    char active_value[96] = "";
    long long cycle_started_at = 0;
    int64_t now = logd_now_s();

    if (critical > 0 && value >= (double)critical)
        severity = "critical";
    else if (warn > 0 && value >= (double)warn)
        severity = "warning";
    snprintf(active_key, sizeof(active_key), "active:%s", metric);
    if (!severity) {
        logd_collector_state_delete("resource", active_key);
        return;
    }
    if (logd_collector_state_get("resource", active_key, active_value,
                                 sizeof(active_value), "") == 0 &&
        active_value[0])
        sscanf(active_value, "%*23[^:]:%lld", &cycle_started_at);
    if (cycle_started_at <= 0)
        cycle_started_at = (long long)now;
    snprintf(active_value, sizeof(active_value), "%s:%lld", severity,
             cycle_started_at);
    logd_collector_state_set("resource", active_key, active_value);

    snprintf(dedupe, sizeof(dedupe), "resource:%s:%lld", metric,
             cycle_started_at);
    snprintf(cooldown_key, sizeof(cooldown_key), "%s:%s", dedupe, severity);
    if (!logd_cooldown_allow("resource", cooldown_key, cooldown_s))
        return;
    if (!strcmp(metric, "temperature"))
        snprintf(title, sizeof(title), "temperature %.1f C", value);
    else
        snprintf(title, sizeof(title), "%s usage %.1f%%", metric, value);
    if (detail)
        json_object_object_add(detail, "value", json_object_new_double(value));
    if (logd_publish_event(severity, "resource", "threshold_exceeded", "resource", "", title, dedupe, detail) == 0)
        logd_cooldown_mark("resource", cooldown_key, cooldown_s);
}

static int logd_read_temperature(double *temperature_c, char *source,
                                 size_t source_len)
{
    DIR *dir;
    struct dirent *de;
    double highest = -1000.0;
    char highest_path[256] = "";

    if (!temperature_c)
        return -1;
    dir = opendir("/sys/class/thermal");
    if (!dir)
        return -1;
    while ((de = readdir(dir)) != NULL) {
        char path[256];
        char value[64];
        char *end = NULL;
        double temp;

        if (strncmp(de->d_name, "thermal_zone", 12))
            continue;
        snprintf(path, sizeof(path), "/sys/class/thermal/%s/temp", de->d_name);
        if (logd_file_read_line(path, value, sizeof(value)) != 0)
            continue;
        errno = 0;
        temp = strtod(value, &end);
        if (errno || !end || (*end && !isspace((unsigned char)*end)))
            continue;
        if (temp > 1000.0)
            temp /= 1000.0;
        if (temp < -50.0 || temp > 200.0 || temp <= highest)
            continue;
        highest = temp;
        snprintf(highest_path, sizeof(highest_path), "%s", path);
    }
    closedir(dir);
    if (highest < -50.0)
        return -1;
    *temperature_c = highest;
    if (source && source_len > 0)
        snprintf(source, source_len, "%s", highest_path);
    return 0;
}

static int logd_collect_resource(struct logd_collector_config *cfg)
{
    struct json_object *opts = logd_json_parse_or_object(cfg ? cfg->options_json : NULL);
    int cpu_warn = logd_json_int(opts, "cpu_warn", 85);
    int cpu_critical = logd_json_int(opts, "cpu_critical", 95);
    int mem_warn = logd_json_int(opts, "mem_warn", 85);
    int mem_critical = logd_json_int(opts, "mem_critical", 95);
    int disk_warn = logd_json_int(opts, "disk_warn", 90);
    int disk_critical = logd_json_int(opts, "disk_critical", 97);
    int inode_warn = logd_json_int(opts, "inode_warn", 90);
    int inode_critical = logd_json_int(opts, "inode_critical", 97);
    int temp_warn = logd_json_int(opts, "temp_warn", 80);
    int temp_critical = logd_json_int(opts, "temp_critical", 90);
    int cooldown_s = cfg ? cfg->cooldown_s : 300;
    double pct = 0.0;
    double disk_pct = 0.0;
    double inode_pct = 0.0;
    double temperature_c = 0.0;
    char temperature_source[256] = "";
    uint64_t mem_total = 0;
    uint64_t mem_avail = 0;
    int rc;

    rc = logd_read_cpu_percent(&pct);
    if (rc == 0) {
        struct json_object *detail = json_object_new_object();
        if (detail) {
            json_object_object_add(detail, "metric", json_object_new_string("cpu"));
            json_object_object_add(detail, "unit", json_object_new_string("percent"));
            json_object_object_add(detail, "warn", json_object_new_int(cpu_warn));
            json_object_object_add(detail, "critical", json_object_new_int(cpu_critical));
        }
        logd_collect_resource_one("cpu", pct, cpu_warn, cpu_critical, cooldown_s, detail);
        if (detail) json_object_put(detail);
    }
    if (logd_read_mem_percent(&pct, &mem_total, &mem_avail) == 0) {
        struct json_object *detail = json_object_new_object();
        if (detail) {
            json_object_object_add(detail, "metric", json_object_new_string("memory"));
            json_object_object_add(detail, "unit", json_object_new_string("percent"));
            json_object_object_add(detail, "total_kb", json_object_new_int64((int64_t)mem_total));
            json_object_object_add(detail, "available_kb", json_object_new_int64((int64_t)mem_avail));
            json_object_object_add(detail, "warn", json_object_new_int(mem_warn));
            json_object_object_add(detail, "critical", json_object_new_int(mem_critical));
        }
        logd_collect_resource_one("memory", pct, mem_warn, mem_critical, cooldown_s, detail);
        if (detail) json_object_put(detail);
    }
    if (logd_disk_percent("/", &disk_pct, &inode_pct) == 0) {
        struct json_object *detail = json_object_new_object();
        if (detail) {
            json_object_object_add(detail, "metric", json_object_new_string("disk"));
            json_object_object_add(detail, "path", json_object_new_string("/"));
            json_object_object_add(detail, "unit", json_object_new_string("percent"));
            json_object_object_add(detail, "warn", json_object_new_int(disk_warn));
            json_object_object_add(detail, "critical", json_object_new_int(disk_critical));
        }
        logd_collect_resource_one("disk", disk_pct, disk_warn, disk_critical, cooldown_s, detail);
        if (detail) json_object_put(detail);
        detail = json_object_new_object();
        if (detail) {
            json_object_object_add(detail, "metric", json_object_new_string("inode"));
            json_object_object_add(detail, "path", json_object_new_string("/"));
            json_object_object_add(detail, "unit", json_object_new_string("percent"));
            json_object_object_add(detail, "warn", json_object_new_int(inode_warn));
            json_object_object_add(detail, "critical", json_object_new_int(inode_critical));
        }
        logd_collect_resource_one("inode", inode_pct, inode_warn, inode_critical, cooldown_s, detail);
        if (detail) json_object_put(detail);
    }
    if (logd_read_temperature(&temperature_c, temperature_source,
                              sizeof(temperature_source)) == 0) {
        struct json_object *detail = json_object_new_object();
        if (detail) {
            json_object_object_add(detail, "metric", json_object_new_string("temperature"));
            json_object_object_add(detail, "unit", json_object_new_string("celsius"));
            json_object_object_add(detail, "source_path", json_object_new_string(temperature_source));
            json_object_object_add(detail, "warn", json_object_new_int(temp_warn));
            json_object_object_add(detail, "critical", json_object_new_int(temp_critical));
        }
        logd_collect_resource_one("temperature", temperature_c, temp_warn,
                                  temp_critical, cooldown_s, detail);
        if (detail) json_object_put(detail);
    }
    if (opts)
        json_object_put(opts);
    return 0;
}

static int logd_port_index(const char *ifname, int create)
{
    size_t i;
    int free_idx = -1;

    if (!ifname || !ifname[0])
        return -1;
    for (i = 0; i < ARRAY_SIZE(g_ports); i++) {
        if (g_ports[i].known && !strcmp(g_ports[i].ifname, ifname))
            return (int)i;
        if (!g_ports[i].known && free_idx < 0)
            free_idx = (int)i;
    }
    if (!create || free_idx < 0)
        return -1;
    memset(&g_ports[free_idx], 0, sizeof(g_ports[free_idx]));
    snprintf(g_ports[free_idx].ifname, sizeof(g_ports[free_idx].ifname), "%s", ifname);
    g_ports[free_idx].known = 1;
    g_ports[free_idx].carrier = -1;
    g_ports[free_idx].speed = -1000000;
    return free_idx;
}

static int logd_iface_skip(const char *ifname)
{
    if (!ifname || !ifname[0])
        return 1;
    if (strlen(ifname) >= sizeof(g_ports[0].ifname))
        return 1;
    if (!strcmp(ifname, "lo"))
        return 1;
    if (!strncmp(ifname, "br-", 3) || !strncmp(ifname, "veth", 4) ||
        !strncmp(ifname, "tun", 3) || !strncmp(ifname, "tap", 3) ||
        !strncmp(ifname, "ifb", 3) || !strncmp(ifname, "docker", 6) ||
        !strncmp(ifname, "wg", 2) || strchr(ifname, '.'))
        return 1;
    return 0;
}

static int logd_collect_ports(struct logd_collector_config *cfg)
{
    DIR *dir;
    struct dirent *de;
    size_t i;
    int changes = 0;
    int cooldown_s = cfg ? cfg->cooldown_s : 30;

    for (i = 0; i < ARRAY_SIZE(g_ports); i++)
        g_ports[i].seen = 0;
    dir = opendir("/sys/class/net");
    if (!dir)
        return -1;
    while ((de = readdir(dir)) != NULL) {
        char path[256];
        char ifname[32];
        size_t ifname_len;
        char oper[32] = "";
        char duplex[32] = "";
        char title[160];
        char dedupe[160];
        int carrier;
        int speed;
        int idx;
        struct logd_port_state *ps;

        if (de->d_name[0] == '.' || logd_iface_skip(de->d_name))
            continue;
        ifname_len = strlen(de->d_name);
        if (ifname_len >= sizeof(ifname))
            continue;
        memcpy(ifname, de->d_name, ifname_len + 1);
        snprintf(path, sizeof(path), "/sys/class/net/%s/device", ifname);
        if (!logd_file_exists(path))
            continue;
        idx = logd_port_index(ifname, 1);
        if (idx < 0)
            continue;
        ps = &g_ports[idx];
        ps->seen = 1;
        snprintf(path, sizeof(path), "/sys/class/net/%s/carrier", ifname);
        carrier = logd_file_read_int(path, 0);
        snprintf(path, sizeof(path), "/sys/class/net/%s/speed", ifname);
        speed = logd_file_read_int(path, -1);
        snprintf(path, sizeof(path), "/sys/class/net/%s/operstate", ifname);
        logd_file_read_line(path, oper, sizeof(oper));
        snprintf(path, sizeof(path), "/sys/class/net/%s/duplex", ifname);
        logd_file_read_line(path, duplex, sizeof(duplex));
        if (ps->carrier == -1) {
            ps->carrier = carrier;
            ps->speed = speed;
            snprintf(ps->operstate, sizeof(ps->operstate), "%s", oper);
            snprintf(ps->duplex, sizeof(ps->duplex), "%s", duplex);
            continue;
        }
        if (ps->carrier != carrier) {
            struct json_object *detail = json_object_new_object();
            snprintf(dedupe, sizeof(dedupe), "port:%s:carrier", ifname);
            snprintf(title, sizeof(title), "%s link %s", ifname, carrier ? "up" : "down");
            if (detail) {
                json_object_object_add(detail, "iface", json_object_new_string(ifname));
                json_object_object_add(detail, "carrier", json_object_new_int(carrier));
                json_object_object_add(detail, "operstate", json_object_new_string(oper));
                json_object_object_add(detail, "speed", json_object_new_int(speed));
                json_object_object_add(detail, "duplex", json_object_new_string(duplex));
            }
            if (logd_cooldown_allow("port", dedupe, cooldown_s) &&
                logd_publish_event(carrier ? "notice" : "warning", "port", carrier ? "link_up" : "link_down",
                                   "port", ifname, title, dedupe, detail) == 0) {
                logd_cooldown_mark("port", dedupe, cooldown_s);
                changes++;
            }
            if (detail) json_object_put(detail);
        } else if (carrier && (ps->speed != speed || strcmp(ps->duplex, duplex))) {
            struct json_object *detail = json_object_new_object();
            snprintf(dedupe, sizeof(dedupe), "port:%s:link_mode", ifname);
            snprintf(title, sizeof(title), "%s link mode changed", ifname);
            if (detail) {
                json_object_object_add(detail, "iface", json_object_new_string(ifname));
                json_object_object_add(detail, "old_speed", json_object_new_int(ps->speed));
                json_object_object_add(detail, "speed", json_object_new_int(speed));
                json_object_object_add(detail, "old_duplex", json_object_new_string(ps->duplex));
                json_object_object_add(detail, "duplex", json_object_new_string(duplex));
            }
            if (logd_cooldown_allow("port", dedupe, cooldown_s) &&
                logd_publish_event("notice", "port", "link_mode_changed", "port", ifname, title, dedupe, detail) == 0) {
                logd_cooldown_mark("port", dedupe, cooldown_s);
                changes++;
            }
            if (detail) json_object_put(detail);
        }
        ps->carrier = carrier;
        ps->speed = speed;
        snprintf(ps->operstate, sizeof(ps->operstate), "%s", oper);
        snprintf(ps->duplex, sizeof(ps->duplex), "%s", duplex);
    }
    closedir(dir);
    for (i = 0; i < ARRAY_SIZE(g_ports); i++) {
        if (g_ports[i].known && !g_ports[i].seen)
            g_ports[i].known = 0;
    }
    return changes;
}

static int logd_dhcp_lease_parse(char *line, struct logd_dhcp_lease *lease)
{
    char *save = NULL;
    char *tok;

    if (!line || !lease)
        return -1;
    memset(lease, 0, sizeof(*lease));
    tok = strtok_r(line, " \t\r\n", &save);
    if (!tok)
        return -1;
    lease->expires = atoll(tok);
    tok = strtok_r(NULL, " \t\r\n", &save);
    if (!tok || !logd_text_ok(tok, sizeof(lease->mac) - 1))
        return -1;
    snprintf(lease->mac, sizeof(lease->mac), "%s", tok);
    tok = strtok_r(NULL, " \t\r\n", &save);
    if (!tok || !logd_text_ok(tok, sizeof(lease->ip) - 1))
        return -1;
    snprintf(lease->ip, sizeof(lease->ip), "%s", tok);
    tok = strtok_r(NULL, " \t\r\n", &save);
    if (tok && strcmp(tok, "*") && logd_text_ok(tok, sizeof(lease->hostname) - 1))
        snprintf(lease->hostname, sizeof(lease->hostname), "%s", tok);
    tok = strtok_r(NULL, " \t\r\n", &save);
    if (tok && strcmp(tok, "*") && logd_text_ok(tok, sizeof(lease->client_id) - 1))
        snprintf(lease->client_id, sizeof(lease->client_id), "%s", tok);
    return lease->mac[0] && lease->ip[0] ? 0 : -1;
}

static int logd_dhcp_lease_seen(const struct logd_dhcp_lease *leases, int count, const char *mac)
{
    int i;

    if (!mac || !mac[0])
        return 0;
    for (i = 0; i < count; i++) {
        if (!strcmp(leases[i].mac, mac))
            return 1;
    }
    return 0;
}

static int logd_dhcp_publish(const char *event, const char *severity,
                             const struct logd_dhcp_lease *lease,
                             const char *old_ip, const char *old_hostname,
                             int cooldown_s)
{
    struct json_object *detail = json_object_new_object();
    char title[192];
    char dedupe[192];
    int rc;

    if (!event || !lease)
        return -1;
    snprintf(title, sizeof(title), "DHCP %s %s %s", event, lease->ip, lease->mac);
    snprintf(dedupe, sizeof(dedupe), "dhcp_lease:%s:%s", event, lease->mac);
    if (!logd_cooldown_allow("dhcp_lease", dedupe, cooldown_s)) {
        if (detail)
            json_object_put(detail);
        return 0;
    }
    if (detail) {
        json_object_object_add(detail, "mac", json_object_new_string(lease->mac));
        json_object_object_add(detail, "ip", json_object_new_string(lease->ip));
        json_object_object_add(detail, "hostname", json_object_new_string(lease->hostname));
        json_object_object_add(detail, "client_id", json_object_new_string(lease->client_id));
        json_object_object_add(detail, "expires", json_object_new_int64(lease->expires));
        if (old_ip && old_ip[0])
            json_object_object_add(detail, "old_ip", json_object_new_string(old_ip));
        if (old_hostname && old_hostname[0])
            json_object_object_add(detail, "old_hostname", json_object_new_string(old_hostname));
    }
    rc = logd_publish_event(severity ? severity : "notice", "dhcp", event,
                            "dhcp_lease", "", title, dedupe, detail) == 0 ? 1 : -1;
    if (rc > 0)
        logd_cooldown_mark("dhcp_lease", dedupe, cooldown_s);
    if (detail)
        json_object_put(detail);
    return rc;
}

static void logd_dhcp_state_key(const char *mac, char *out, size_t out_len)
{
    snprintf(out, out_len, "lease:%s", mac ? mac : "");
}

static void logd_dhcp_state_encode(const struct logd_dhcp_lease *lease, char *out, size_t out_len)
{
    struct json_object *o;
    const char *s;

    if (!out || out_len == 0)
        return;
    snprintf(out, out_len, "%s", "{}");
    if (!lease)
        return;
    o = json_object_new_object();
    if (!o)
        return;
    json_object_object_add(o, "ip", json_object_new_string(lease->ip));
    json_object_object_add(o, "hostname", json_object_new_string(lease->hostname));
    json_object_object_add(o, "expires", json_object_new_int64(lease->expires));
    s = json_object_to_json_string(o);
    if (s && strlen(s) < out_len)
        snprintf(out, out_len, "%s", s);
    json_object_put(o);
}

static void logd_dhcp_state_decode(const char *s, char *ip, size_t ip_len,
                                   char *hostname, size_t hostname_len, int64_t *expires)
{
    struct json_object *o;

    if (ip && ip_len > 0) ip[0] = '\0';
    if (hostname && hostname_len > 0) hostname[0] = '\0';
    if (expires) *expires = 0;
    o = logd_json_parse_or_object(s);
    if (ip && ip_len > 0)
        snprintf(ip, ip_len, "%s", logd_json_str(o, "ip", ""));
    if (hostname && hostname_len > 0)
        snprintf(hostname, hostname_len, "%s", logd_json_str(o, "hostname", ""));
    if (expires)
        *expires = logd_json_i64(o, "expires", 0);
    json_object_put(o);
}

static int logd_collect_dhcp_leases(struct logd_collector_config *cfg)
{
    FILE *fp;
    char line[384];
    struct logd_dhcp_lease leases[LOGD_MAX_DHCP_LEASES];
    int count = 0;
    int events = 0;
    int initialized = 0;
    char init[8];
    sqlite3_stmt *st;
    int i;
    int rc;
    int cooldown_s = cfg ? cfg->cooldown_s : 0;

    fp = fopen(LOGD_DHCP_LEASE_PATH, "r");
    if (!fp)
        return 0;
    memset(leases, 0, sizeof(leases));
    while (count < LOGD_MAX_DHCP_LEASES && fgets(line, sizeof(line), fp)) {
        struct logd_dhcp_lease lease;

        if (logd_dhcp_lease_parse(line, &lease) == 0)
            leases[count++] = lease;
    }
    fclose(fp);
    rc = logd_collector_state_get("dhcp_lease", "initialized", init, sizeof(init), "0");
    if (rc < 0)
        return -1;
    if (rc == 0 && !strcmp(init, "1"))
        initialized = 1;
    for (i = 0; i < count; i++) {
        char key[96];
        char previous[384];
        char next[384];
        char old_ip[64] = "";
        char old_hostname[128] = "";
        int64_t old_expires = 0;
        int publish_rc = 0;

        logd_dhcp_state_key(leases[i].mac, key, sizeof(key));
        logd_dhcp_state_encode(&leases[i], next, sizeof(next));
        rc = logd_collector_state_get("dhcp_lease", key, previous, sizeof(previous), "");
        if (rc < 0)
            return -1;
        if (rc == 0 && previous[0]) {
            logd_dhcp_state_decode(previous, old_ip, sizeof(old_ip), old_hostname, sizeof(old_hostname), &old_expires);
            if (initialized) {
                if (strcmp(old_ip, leases[i].ip) || strcmp(old_hostname, leases[i].hostname)) {
                    publish_rc = logd_dhcp_publish("lease_changed", "notice", &leases[i], old_ip, old_hostname, cooldown_s);
                } else if (leases[i].expires > old_expires) {
                    publish_rc = logd_dhcp_publish("lease_renewed", "info", &leases[i], NULL, NULL, cooldown_s);
                }
            }
        } else if (initialized) {
            publish_rc = logd_dhcp_publish("lease_assigned", "notice", &leases[i], NULL, NULL, cooldown_s);
        }
        if (publish_rc < 0)
            return -1;
        if (publish_rc > 0)
            events++;
        if (logd_collector_state_set("dhcp_lease", key, next) != 0)
            return -1;
    }
    if (initialized) {
        st = logd_config_prepare(
            "SELECT key,value FROM logd_collector_state WHERE name='dhcp_lease' AND key LIKE 'lease:%'");
        if (!st)
            return -1;
        while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
            const char *key = (const char *)sqlite3_column_text(st, 0);
            const char *value = (const char *)sqlite3_column_text(st, 1);
            const char *mac = key && !strncmp(key, "lease:", 6) ? key + 6 : "";
            struct logd_dhcp_lease lease;

            if (!mac[0] || logd_dhcp_lease_seen(leases, count, mac))
                continue;
            memset(&lease, 0, sizeof(lease));
            snprintf(lease.mac, sizeof(lease.mac), "%s", mac);
            if (value)
                logd_dhcp_state_decode(value, lease.ip, sizeof(lease.ip), lease.hostname, sizeof(lease.hostname), &lease.expires);
            rc = logd_dhcp_publish("lease_released", "notice", &lease, NULL, NULL, cooldown_s);
            if (rc < 0) {
                sqlite3_finalize(st);
                return -1;
            }
            if (logd_collector_state_delete("dhcp_lease", key) != 0) {
                sqlite3_finalize(st);
                return -1;
            }
            if (rc > 0)
                events++;
        }
        sqlite3_finalize(st);
        if (rc != SQLITE_DONE)
            return -1;
    }
    if (logd_collector_state_set("dhcp_lease", "initialized", "1") != 0)
        return -1;
    return events;
}

static int logd_run_collector(const char *name, int force)
{
    struct logd_collector_runtime *rt = logd_collector_runtime_find(name);
    struct logd_collector_config cfg;
    int64_t now = logd_now_s();
    int rc = 0;

    if (!rt || logd_collector_config_load(name, &cfg) != 0)
        return -1;
    if (!cfg.enabled && !force)
        return 0;
    if (!force && rt->last_run > 0 && now - rt->last_run < cfg.interval_s)
        return 0;
    if (!strcmp(name, "system_log"))
        rc = logd_collect_logread(name, 0, cfg.cooldown_s);
    else if (!strcmp(name, "kernel_log"))
        rc = logd_collect_logread(name, 1, cfg.cooldown_s);
    else if (!strcmp(name, "resource"))
        rc = logd_collect_resource(&cfg);
    else if (!strcmp(name, "port"))
        rc = logd_collect_ports(&cfg);
    else if (!strcmp(name, "dhcp_lease"))
        rc = logd_collect_dhcp_leases(&cfg);
    else
        rc = -1;
    logd_runtime_note(rt, rc >= 0, rc >= 0 ? NULL : "collector_run_failed");
    return rc;
}

static void logd_collect_timer_cb(struct uloop_timeout *t)
{
    static int64_t last_state_prune;
    size_t i;
    int64_t now = logd_now_s();
    (void)t;

    if (jmx_storage_guard_allow("/", JMX_STORAGE_WRITE_BULK, NULL)) {
        for (i = 0; i < ARRAY_SIZE(g_collectors); i++)
            logd_run_collector(g_collectors[i].name, 0);
    } else {
        g_logd_storage_suppressed++;
        g_logd_storage_last_suppressed_at = now;
    }
    /* Keep draining an existing remote queue while local bulk collection is
     * paused. This bounds storage and still delivers critical events. */
    logd_syslog_process_queue(LOGD_SYSLOG_QUEUE_BATCH);
    if (last_state_prune <= 0 || now - last_state_prune >= 3600) {
        if (logd_collector_state_prune() == 0)
            last_state_prune = now;
    }
    uloop_timeout_set(&g_collect_timer, LOGD_COLLECT_TICK_MS);
}

static void logd_collectors_set_first_error(struct json_object *resp, const char *error)
{
    struct json_object *existing = NULL;

    if (!resp || !error || !error[0])
        return;
    if (json_object_object_get_ex(resp, "error", &existing) && existing)
        return;
    json_object_object_add(resp, "error", json_object_new_string(error));
}

struct json_object *logd_collectors_json(void)
{
    sqlite3_stmt *st;
    struct json_object *resp = json_object_new_object();
    struct json_object *arr = json_object_new_array();
    size_t i;
    int ok = 1;
    int rc;

    for (i = 0; i < ARRAY_SIZE(g_collectors); i++) {
        struct logd_collector_config cfg;
        struct json_object *o = json_object_new_object();

        if (!o)
            continue;
        if (logd_collector_config_load(g_collectors[i].name, &cfg) != 0) {
            logd_collector_config_default(g_collectors[i].name, &cfg);
            ok = 0;
            logd_collectors_set_first_error(resp, "collector_config_query_failed");
        }
        json_object_object_add(o, "name", json_object_new_string(g_collectors[i].name));
        json_object_object_add(o, "enabled", json_object_new_boolean(cfg.enabled));
        json_object_object_add(o, "interval_s", json_object_new_int(cfg.interval_s));
        json_object_object_add(o, "cooldown_s", json_object_new_int(cfg.cooldown_s));
        json_object_object_add(o, "options", logd_json_parse_or_object(cfg.options_json));
        json_object_object_add(o, "last_run", json_object_new_int64(g_collectors[i].last_run));
        json_object_object_add(o, "last_ok", json_object_new_int64(g_collectors[i].last_ok));
        json_object_object_add(o, "runs", json_object_new_int64((int64_t)g_collectors[i].runs));
        json_object_object_add(o, "errors", json_object_new_int64((int64_t)g_collectors[i].errors));
        json_object_object_add(o, "last_error", json_object_new_string(g_collectors[i].last_error));
        json_object_array_add(arr, o);
    }
    st = logd_config_prepare("SELECT COUNT(*) FROM logd_collector_state");
    if (st) {
        rc = sqlite3_step(st);
        if (rc == SQLITE_ROW)
            json_object_object_add(resp, "state_keys", json_object_new_int64(sqlite3_column_int64(st, 0)));
        else {
            ok = 0;
            logd_collectors_set_first_error(resp, "collector_state_query_failed");
        }
        sqlite3_finalize(st);
    } else {
        ok = 0;
        logd_collectors_set_first_error(resp, "collector_state_query_failed");
    }
    json_object_object_add(resp, "ok", json_object_new_boolean(ok));
    json_object_object_add(resp, "collectors", arr);
    return resp;
}

struct json_object *logd_collectors_update(struct json_object *body)
{
    const char *name = logd_json_str(body, "name", "");
    struct logd_collector_config cfg;
    int enabled;
    int interval_s;
    int cooldown_s;
    struct json_object *options = NULL;
    const char *options_s;
    sqlite3_stmt *st;
    struct json_object *resp = json_object_new_object();

    if (logd_collector_name_ok(name)) {
        if (logd_collector_config_load(name, &cfg) != 0) {
            json_object_object_add(resp, "ok", json_object_new_boolean(0));
            json_object_object_add(resp, "error", json_object_new_string("collector_config_query_failed"));
            return resp;
        }
    } else {
        memset(&cfg, 0, sizeof(cfg));
    }
    enabled = logd_json_bool(body, "enabled", cfg.enabled);
    interval_s = logd_json_int(body, "interval_s", cfg.interval_s);
    cooldown_s = logd_json_int(body, "cooldown_s", cfg.cooldown_s);
    options_s = cfg.options_json[0] ? cfg.options_json : "{}";
    if (!logd_collector_name_ok(name) || interval_s < 2 || interval_s > 86400 || cooldown_s < 0 || cooldown_s > 86400) {
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("invalid_collector_settings"));
        return resp;
    }
    if (json_object_object_get_ex(body, "options", &options) && options)
        options_s = json_object_to_json_string(options);
    if (!options_s || strlen(options_s) >= LOGD_MAX_OPTIONS_JSON) {
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("invalid_collector_options"));
        return resp;
    }
    st = logd_config_prepare(
        "INSERT OR REPLACE INTO logd_collector_settings(name,enabled,interval_s,cooldown_s,options_json,updated_at) "
        "VALUES(?1,?2,?3,?4,?5,?6)");
    if (!st) {
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("collector_settings_prepare_failed"));
        return resp;
    }
    sqlite3_bind_text(st, 1, name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 2, enabled ? 1 : 0);
    sqlite3_bind_int(st, 3, interval_s);
    sqlite3_bind_int(st, 4, cooldown_s);
    sqlite3_bind_text(st, 5, options_s, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 6, logd_now_s());
    if (sqlite3_step(st) != SQLITE_DONE) {
        sqlite3_finalize(st);
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("collector_settings_update_failed"));
        return resp;
    }
    sqlite3_finalize(st);
    json_object_put(resp);
    return logd_collectors_json();
}

struct json_object *logd_collect_now(struct json_object *body)
{
    const char *name = logd_json_str(body, "name", "");
    struct json_object *resp = json_object_new_object();
    struct json_object *arr = json_object_new_array();
    int failed = 0;
    int ran = 0;
    size_t i;

    if (name[0] && !logd_collector_name_ok(name)) {
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("unknown_collector"));
        json_object_put(arr);
        return resp;
    }
    for (i = 0; i < ARRAY_SIZE(g_collectors); i++) {
        struct json_object *o;
        int rc;

        if (name[0] && strcmp(name, g_collectors[i].name))
            continue;
        rc = logd_run_collector(g_collectors[i].name, 1);
        ran++;
        if (rc < 0)
            failed++;
        o = json_object_new_object();
        if (!o)
            continue;
        json_object_object_add(o, "name", json_object_new_string(g_collectors[i].name));
        json_object_object_add(o, "ok", json_object_new_boolean(rc >= 0));
        json_object_object_add(o, "result", json_object_new_int(rc));
        json_object_array_add(arr, o);
    }
    json_object_object_add(resp, "ok", json_object_new_boolean(ran > 0 && failed == 0));
    json_object_object_add(resp, "ran", json_object_new_int(ran));
    json_object_object_add(resp, "failed", json_object_new_int(failed));
    if (failed > 0)
        json_object_object_add(resp, "error", json_object_new_string("collector_run_failed"));
    json_object_object_add(resp, "results", arr);
    return resp;
}

void logd_collectors_start(void)
{
    g_collect_timer.cb = logd_collect_timer_cb;
    uloop_timeout_set(&g_collect_timer, LOGD_COLLECT_TICK_MS);
}

void logd_collectors_stop(void)
{
    uloop_timeout_cancel(&g_collect_timer);
}
