// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>
 *
 * Read-only resource-manager monitoring routes plus process signal delivery.
 *
 * Threading contract: every handler here is called from jmx_api_router_dispatch
 * inside the webd pool worker that owns the connection. webd is a pre-forked
 * pool, so a /proc walk here never touches core's single uloop control-plane
 * thread -- which is the whole point, because an unbounded /proc read on that
 * thread froze the box once already (the maintenance-io-worker fix). Nothing
 * here calls into core over ubus.
 *
 * Rate figures (CPU %, interface bps) are computed by in-request double
 * sampling: read, nanosleep, read, diff. webd's persistent workers share no
 * memory and requests are not pinned to a worker, so a cross-request "last
 * snapshot" cannot be trusted; the double sample makes sample_interval_ms
 * deterministic at the cost of one short sleep on the serving worker.
 */
#define _GNU_SOURCE

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <pwd.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "../../jmx_strbuf.h"
#include "../jmx_app_api.h"
#include "api_context.h"
#include "api_error.h"
#include "api_json.h"
#include "api_request.h"
#include "api_router.h"
#include "api_system_monitor.h"

/* ── tunables ───────────────────────────────────────────────────────────── */

/* Sample window for rate deltas. 500ms keeps a poll snappy while giving CPU%
 * and bps enough spread to be stable. Clamped range for the ?interval_ms hint. */
#define SM_SAMPLE_MS_DEFAULT 500
#define SM_SAMPLE_MS_MIN     200
#define SM_SAMPLE_MS_MAX     2000

/* Upper bound on pids materialised into the process table in one request, and
 * on the rows returned. A busy box tops out ~250 pids; the cap is a guard, not
 * a normal limit. */
#define SM_PROC_SCAN_MAX     4096
#define SM_PROC_RETURN_MAX   512
#define SM_PROC_RETURN_DEFAULT 200

#define SM_INITD_DIR   "/etc/init.d"
#define SM_RCD_DIR     "/etc/rc.d"
#define SM_INITD_MAX   1024

/* Signals the process-signal route will deliver. Anything else is refused. */
struct sm_signal_map { const char *name; int sig; };
static const struct sm_signal_map sm_allowed_signals[] = {
    { "TERM", SIGTERM }, { "KILL", SIGKILL }, { "HUP", SIGHUP },
    { "INT", SIGINT }, { "QUIT", SIGQUIT }, { "USR1", SIGUSR1 },
    { "USR2", SIGUSR2 }, { "STOP", SIGSTOP }, { "CONT", SIGCONT },
};

/* Process names that must never be signalled through this route: killing any
 * of them can drop the control plane, the network, or the admin UI. Matched
 * against /proc/<pid>/stat comm (truncated to 15 chars by the kernel), so the
 * daemon entries are pre-truncated to what comm actually reports. */
static const char *sm_protected_comm[] = {
    "dreamingwrt-ini",  /* dreamingwrt-init, comm truncated at 15 */
    "dreamingwrt-cor",  /* dreamingwrt-core */
    "dreamingwrt-web",  /* dreamingwrt-webd (this pool) */
    "netifd", "firewall", "rpcd", "procd", "ubusd", "dropbear",
    "init", "netconfigd",
};

/* ── /proc helpers ──────────────────────────────────────────────────────── */

/* Read a whole small file into buf (NUL-terminated). Returns bytes read, or -1.
 * A single read() is enough for the /proc nodes we touch; they are produced in
 * one shot and are well under a page. */
static ssize_t sm_read_file(const char *path, char *buf, size_t buflen)
{
    int fd;
    ssize_t n;

    if (buflen == 0)
        return -1;
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    n = read(fd, buf, buflen - 1);
    close(fd);
    if (n < 0)
        return -1;
    buf[n] = '\0';
    return n;
}

static int64_t sm_now_ms(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return -1;
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void sm_sleep_ms(int ms)
{
    struct timespec ts;
    if (ms <= 0)
        return;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (long)(ms % 1000) * 1000000L;
    while (nanosleep(&ts, &ts) != 0 && errno == EINTR)
        ;
}

/* Clamp a caller-supplied ?interval_ms into the safe window. */
static int sm_sample_interval(struct jmx_api_ctx *ctx)
{
    char raw[16] = "";
    int ms = SM_SAMPLE_MS_DEFAULT;

    if (ctx && ctx->req &&
        webd_query_get(ctx->req->query, "interval_ms", raw, sizeof(raw)) == 0 &&
        raw[0]) {
        int v = atoi(raw);
        if (v > 0)
            ms = v;
    }
    if (ms < SM_SAMPLE_MS_MIN)
        ms = SM_SAMPLE_MS_MIN;
    if (ms > SM_SAMPLE_MS_MAX)
        ms = SM_SAMPLE_MS_MAX;
    return ms;
}

/* Wrap a data object in the standard { ok, data, meta, code: 2000 } envelope
 * the frontend expects, matching webd_kernel_runtime_response(). */
static struct json_object *sm_envelope(struct json_object *data, const char *source)
{
    struct json_object *resp = webd_envelope(data, source);
    json_object_object_add(resp, "code", json_object_new_int(APP_API_CODE_SUCCESS));
    return resp;
}

/* ── /proc/stat aggregate + per-core ────────────────────────────────────── */

#define SM_MAX_CORES 256

struct sm_cpu_times {
    uint64_t total;   /* sum of all fields */
    uint64_t idle;    /* idle + iowait */
};

/* Parse one "cpu..." line's jiffie fields into total/idle. */
static void sm_parse_cpu_line(const char *line, struct sm_cpu_times *out)
{
    uint64_t v[10];
    int i, n;
    const char *p = line;
    uint64_t total = 0;

    memset(v, 0, sizeof(v));
    /* skip the "cpuN" label */
    while (*p && !isspace((unsigned char)*p))
        p++;
    n = 0;
    for (i = 0; i < 10 && *p; i++) {
        while (*p == ' ' || *p == '\t')
            p++;
        if (*p < '0' || *p > '9')
            break;
        v[i] = strtoull(p, (char **)&p, 10);
        n++;
    }
    for (i = 0; i < n; i++)
        total += v[i];
    out->total = total;
    out->idle = v[3] + v[4]; /* idle + iowait */
}

/* Snapshot aggregate + up to SM_MAX_CORES per-core times. Returns core count. */
static int sm_read_cpu_snapshot(struct sm_cpu_times *agg,
                                struct sm_cpu_times *cores, int max_cores)
{
    char buf[8192];
    char *line, *save;
    int ncore = 0;

    agg->total = agg->idle = 0;
    if (sm_read_file("/proc/stat", buf, sizeof(buf)) < 0)
        return -1;
    line = strtok_r(buf, "\n", &save);
    while (line) {
        if (!strncmp(line, "cpu ", 4)) {
            sm_parse_cpu_line(line, agg);
        } else if (!strncmp(line, "cpu", 3) &&
                   line[3] >= '0' && line[3] <= '9') {
            if (ncore < max_cores)
                sm_parse_cpu_line(line, &cores[ncore]);
            ncore++;
        } else if (strncmp(line, "cpu", 3) != 0) {
            break; /* cpu lines are contiguous at the top of /proc/stat */
        }
        line = strtok_r(NULL, "\n", &save);
    }
    return ncore;
}

/* busy% between two snapshots of one cpu line. */
static double sm_cpu_busy_pct(const struct sm_cpu_times *a,
                              const struct sm_cpu_times *b)
{
    uint64_t dt = (b->total >= a->total) ? b->total - a->total : 0;
    uint64_t di = (b->idle  >= a->idle)  ? b->idle  - a->idle  : 0;
    if (dt == 0)
        return 0.0;
    if (di > dt)
        di = dt;
    return (double)(dt - di) * 100.0 / (double)dt;
}

static double sm_round1(double v)
{
    return (double)((int)(v * 10.0 + (v >= 0 ? 0.5 : -0.5))) / 10.0;
}

/* Human CPU label + core count + max freq. aarch64 has no x86 "model name" we
 * can trust, so device-tree model is the label; core count is the processor
 * line count; max freq is from cpufreq sysfs. */
static void sm_cpu_static_info(struct json_object *data, int core_count_seen)
{
    char buf[4096];
    char label[256] = "";
    int cores = 0;
    long max_khz = 0, cur_khz = 0;
    char arch[32] = "";

    /* human label: /tmp/sysinfo/model, else device-tree, else cpuinfo model name */
    if (sm_read_file("/tmp/sysinfo/model", buf, sizeof(buf)) > 0) {
        char *nl = strchr(buf, '\n');
        if (nl) *nl = '\0';
        JMX_STRBUF_COPY(label, buf);
    } else if (sm_read_file("/proc/device-tree/model", buf, sizeof(buf)) > 0) {
        JMX_STRBUF_COPY(label, buf);
    }

    if (sm_read_file("/proc/cpuinfo", buf, sizeof(buf)) > 0) {
        char *line, *save;
        char copy[4096];
        snprintf(copy, sizeof(copy), "%s", buf);
        line = strtok_r(copy, "\n", &save);
        while (line) {
            if (!strncmp(line, "processor", 9))
                cores++;
            else if (!label[0] && !strncmp(line, "model name", 10)) {
                const char *c = strchr(line, ':');
                if (c) {
                    c++;
                    while (*c == ' ' || *c == '\t') c++;
                    snprintf(label, sizeof(label), "%s", c);
                }
            } else if (!arch[0] && !strncmp(line, "CPU architecture", 16)) {
                const char *c = strchr(line, ':');
                if (c) {
                    c++;
                    while (*c == ' ' || *c == '\t') c++;
                    snprintf(arch, sizeof(arch), "ARMv%s", c);
                }
            }
            line = strtok_r(NULL, "\n", &save);
        }
    }
    if (cores == 0)
        cores = core_count_seen;

    if (sm_read_file("/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq",
                     buf, sizeof(buf)) > 0)
        max_khz = atol(buf);
    if (sm_read_file("/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq",
                     buf, sizeof(buf)) > 0)
        cur_khz = atol(buf);

    json_object_object_add(data, "board_model",
                           json_object_new_string(label[0] ? label : "unknown"));
    json_object_object_add(data, "core_count", json_object_new_int(cores));
    json_object_object_add(data, "max_freq_khz", json_object_new_int64(max_khz));
    json_object_object_add(data, "cur_freq_khz", json_object_new_int64(cur_khz));
    if (arch[0])
        json_object_object_add(data, "arch", json_object_new_string(arch));
}

static struct json_object *sm_cpu_data(struct jmx_api_ctx *ctx)
{
    struct json_object *data = json_object_new_object();
    struct json_object *per_core = json_object_new_array();
    struct sm_cpu_times agg1, agg2, cores1[SM_MAX_CORES], cores2[SM_MAX_CORES];
    int n1, n2, i, interval;

    interval = sm_sample_interval(ctx);
    n1 = sm_read_cpu_snapshot(&agg1, cores1, SM_MAX_CORES);
    if (n1 < 0) {
        json_object_put(per_core);
        json_object_object_add(data, "available", json_object_new_boolean(0));
        json_object_object_add(data, "reason", json_object_new_string("proc_stat_unavailable"));
        return data;
    }
    sm_sleep_ms(interval);
    n2 = sm_read_cpu_snapshot(&agg2, cores2, SM_MAX_CORES);
    if (n2 < 0)
        n2 = 0;

    json_object_object_add(data, "available", json_object_new_boolean(1));
    json_object_object_add(data, "aggregate_percent",
                           json_object_new_double(sm_round1(sm_cpu_busy_pct(&agg1, &agg2))));
    {
        int nc = (n1 < n2) ? n1 : n2;
        if (nc > SM_MAX_CORES) nc = SM_MAX_CORES;
        for (i = 0; i < nc; i++)
            json_object_array_add(per_core,
                json_object_new_double(sm_round1(sm_cpu_busy_pct(&cores1[i], &cores2[i]))));
    }
    json_object_object_add(data, "per_core", per_core);
    json_object_object_add(data, "sample_interval_ms", json_object_new_int(interval));
    sm_cpu_static_info(data, n1);
    return data;
}

static struct json_object *sm_handle_cpu(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = sm_envelope(sm_cpu_data(ctx), "webd.system_monitor.cpu");
    ctx->status = 200;
    return resp;
}

/* ── /proc/net/dev per-interface throughput ─────────────────────────────── */

#define SM_MAX_IFACES 64
#define SM_IFNAME_MAX 32

struct sm_iface_counters {
    char     name[SM_IFNAME_MAX];
    uint64_t rx_bytes, rx_packets, rx_errors, rx_drop;
    uint64_t tx_bytes, tx_packets, tx_errors, tx_drop;
};

/* Snapshot every interface line in /proc/net/dev. Returns count, or -1. */
static int sm_read_netdev(struct sm_iface_counters *ifs, int max)
{
    char buf[16384];
    char *line, *save;
    int count = 0;

    if (sm_read_file("/proc/net/dev", buf, sizeof(buf)) < 0)
        return -1;
    line = strtok_r(buf, "\n", &save);
    while (line) {
        char *colon = strchr(line, ':');
        if (colon && count < max) {
            struct sm_iface_counters *c = &ifs[count];
            char *p = line;
            const char *name;
            uint64_t v[16];
            int i;

            while (*p == ' ' || *p == '\t')
                p++;
            *colon = '\0';
            name = p;
            memset(c, 0, sizeof(*c));
            snprintf(c->name, sizeof(c->name), "%s", name);
            p = colon + 1;
            memset(v, 0, sizeof(v));
            for (i = 0; i < 16; i++) {
                while (*p == ' ' || *p == '\t')
                    p++;
                if (*p < '0' || *p > '9')
                    break;
                v[i] = strtoull(p, &p, 10);
            }
            /* /proc/net/dev order: rx bytes packets errs drop fifo frame
             * compressed multicast | tx bytes packets errs drop ... */
            c->rx_bytes = v[0]; c->rx_packets = v[1]; c->rx_errors = v[2]; c->rx_drop = v[3];
            c->tx_bytes = v[8]; c->tx_packets = v[9]; c->tx_errors = v[10]; c->tx_drop = v[11];
            count++;
        }
        line = strtok_r(NULL, "\n", &save);
    }
    return count;
}

static int sm_iface_is_virtual(const char *name)
{
    return !strcmp(name, "lo") ||
           !strncmp(name, "docker", 6) ||
           !strncmp(name, "veth", 4) ||
           !strncmp(name, "gre", 3) ||
           !strncmp(name, "gretap", 6) ||
           !strncmp(name, "ifb", 3) ||
           !strncmp(name, "cpu", 3) ||   /* DSA cpu ports */
           !strncmp(name, "sit", 3) ||
           !strncmp(name, "ip6tnl", 6) ||
           !strncmp(name, "teql", 4);
}

/* carrier state from /sys/class/net/<name>/carrier (1 up, 0 down, -1 unknown) */
static int sm_iface_carrier(const char *name)
{
    char path[128], buf[8];
    if (snprintf(path, sizeof(path), "/sys/class/net/%s/carrier", name) >= (int)sizeof(path))
        return -1;
    if (sm_read_file(path, buf, sizeof(buf)) < 0)
        return -1;
    return buf[0] == '1' ? 1 : 0;
}

static struct json_object *sm_interfaces_data(struct jmx_api_ctx *ctx)
{
    struct json_object *data = json_object_new_object();
    struct json_object *arr = json_object_new_array();
    struct sm_iface_counters a[SM_MAX_IFACES], b[SM_MAX_IFACES];
    int na, nb, i, interval;
    double dt_s;

    interval = sm_sample_interval(ctx);
    na = sm_read_netdev(a, SM_MAX_IFACES);
    if (na < 0) {
        json_object_put(arr);
        json_object_object_add(data, "available", json_object_new_boolean(0));
        json_object_object_add(data, "reason", json_object_new_string("proc_net_dev_unavailable"));
        return data;
    }
    sm_sleep_ms(interval);
    nb = sm_read_netdev(b, SM_MAX_IFACES);
    if (nb < 0)
        nb = 0;
    dt_s = (double)interval / 1000.0;
    if (dt_s <= 0)
        dt_s = 1.0;

    json_object_object_add(data, "available", json_object_new_boolean(1));
    for (i = 0; i < na; i++) {
        struct json_object *o = json_object_new_object();
        struct sm_iface_counters *cur = &a[i];
        struct sm_iface_counters *later = NULL;
        uint64_t rx_bps = 0, tx_bps = 0;
        int carrier;
        int j;

        for (j = 0; j < nb; j++) {
            if (!strcmp(b[j].name, cur->name)) { later = &b[j]; break; }
        }
        if (later) {
            uint64_t drx = later->rx_bytes >= cur->rx_bytes ? later->rx_bytes - cur->rx_bytes : 0;
            uint64_t dtx = later->tx_bytes >= cur->tx_bytes ? later->tx_bytes - cur->tx_bytes : 0;
            rx_bps = (uint64_t)((double)drx / dt_s);
            tx_bps = (uint64_t)((double)dtx / dt_s);
            /* report the fresher absolute counters */
            cur = later;
        }
        carrier = sm_iface_carrier(cur->name);

        json_object_object_add(o, "name", json_object_new_string(cur->name));
        json_object_object_add(o, "rx_bps", json_object_new_int64((int64_t)rx_bps));
        json_object_object_add(o, "tx_bps", json_object_new_int64((int64_t)tx_bps));
        json_object_object_add(o, "rx_bytes", json_object_new_int64((int64_t)cur->rx_bytes));
        json_object_object_add(o, "tx_bytes", json_object_new_int64((int64_t)cur->tx_bytes));
        json_object_object_add(o, "rx_errors", json_object_new_int64((int64_t)cur->rx_errors));
        json_object_object_add(o, "tx_errors", json_object_new_int64((int64_t)cur->tx_errors));
        json_object_object_add(o, "rx_drop", json_object_new_int64((int64_t)cur->rx_drop));
        json_object_object_add(o, "tx_drop", json_object_new_int64((int64_t)cur->tx_drop));
        if (carrier >= 0)
            json_object_object_add(o, "carrier", json_object_new_boolean(carrier));
        else
            json_object_object_add(o, "carrier", NULL);
        json_object_object_add(o, "virtual",
                               json_object_new_boolean(sm_iface_is_virtual(cur->name)));
        json_object_array_add(arr, o);
    }
    json_object_object_add(data, "interfaces", arr);
    json_object_object_add(data, "sample_interval_ms", json_object_new_int(interval));
    return data;
}

static struct json_object *sm_handle_interfaces(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = sm_envelope(sm_interfaces_data(ctx),
                                           "webd.system_monitor.interfaces");
    ctx->status = 200;
    return resp;
}

/* ── process list ───────────────────────────────────────────────────────── */

struct sm_proc {
    int      pid;
    int      ppid;
    char     comm[24];      /* /proc/<pid>/stat field 2, kernel-truncated */
    char     state;
    uint64_t jiffies;       /* utime + stime at sample time */
    uint64_t rss_bytes;
    int      threads;
    uid_t    uid;
};

/* Parse pid, comm, state, ppid, utime+stime, rss, threads from a stat line.
 * comm can contain spaces and parens, so it is delimited by the last ')'. */
static int sm_parse_proc_stat(const char *buf, struct sm_proc *p)
{
    const char *rp;
    const char *lp = strchr(buf, '(');
    long pagesize = sysconf(_SC_PAGESIZE);
    uint64_t utime = 0, stime = 0, rss_pages = 0;
    int threads = 0;
    char state = '?';
    int ppid = 0;

    if (!lp)
        return -1;
    rp = strrchr(lp, ')');
    if (!rp)
        return -1;
    p->pid = atoi(buf);
    {
        size_t len = (size_t)(rp - (lp + 1));
        if (len >= sizeof(p->comm))
            len = sizeof(p->comm) - 1;
        memcpy(p->comm, lp + 1, len);
        p->comm[len] = '\0';
    }
    /* Fields after ")": state(3) ppid(4) ... utime(14) stime(15) ...
     * num_threads(20) ... rss(24). Index from field 3 = token 0 here. */
    {
        const char *q = rp + 1;
        int idx = 3; /* next token is field 3 (state) */
        char token[64];
        while (*q == ' ') q++;
        while (*q) {
            int ti = 0;
            while (*q && *q != ' ' && ti < (int)sizeof(token) - 1)
                token[ti++] = *q++;
            token[ti] = '\0';
            while (*q == ' ') q++;
            switch (idx) {
            case 3:  state = token[0]; break;
            case 4:  ppid = atoi(token); break;
            case 14: utime = strtoull(token, NULL, 10); break;
            case 15: stime = strtoull(token, NULL, 10); break;
            case 20: threads = atoi(token); break;
            case 24: rss_pages = strtoull(token, NULL, 10); break;
            default: break;
            }
            idx++;
            if (idx > 24)
                break;
        }
    }
    p->state = state;
    p->ppid = ppid;
    p->jiffies = utime + stime;
    p->threads = threads;
    p->rss_bytes = rss_pages * (pagesize > 0 ? (uint64_t)pagesize : 4096);
    return 0;
}

/* Snapshot every /proc/<pid>/stat. Returns count into out (capped at max). */
static int sm_read_proc_snapshot(struct sm_proc *out, int max)
{
    DIR *d = opendir("/proc");
    struct dirent *e;
    int count = 0;

    if (!d)
        return -1;
    while ((e = readdir(d)) != NULL && count < max) {
        char path[64], buf[4096];
        struct sm_proc p;
        struct stat st;
        int pid;

        if (e->d_name[0] < '0' || e->d_name[0] > '9')
            continue;
        pid = atoi(e->d_name);
        if (pid <= 0)
            continue;
        snprintf(path, sizeof(path), "/proc/%d/stat", pid);
        if (sm_read_file(path, buf, sizeof(buf)) < 0)
            continue;
        memset(&p, 0, sizeof(p));
        if (sm_parse_proc_stat(buf, &p) != 0)
            continue;
        /* owner uid from the stat file's inode */
        snprintf(path, sizeof(path), "/proc/%d", pid);
        p.uid = (stat(path, &st) == 0) ? st.st_uid : (uid_t)-1;
        out[count++] = p;
    }
    closedir(d);
    return count;
}

/* Resolve a full cmdline (NUL-separated -> space-joined) for one pid. */
static void sm_read_cmdline(int pid, char *out, size_t outlen)
{
    char path[64], buf[4096];
    ssize_t n;
    size_t i;

    out[0] = '\0';
    snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
    n = sm_read_file(path, buf, sizeof(buf));
    if (n <= 0)
        return;
    for (i = 0; i < (size_t)n && i < outlen - 1; i++)
        out[i] = buf[i] ? buf[i] : ' ';
    out[i] = '\0';
    /* trim trailing space */
    while (i > 0 && out[i - 1] == ' ')
        out[--i] = '\0';
}

static const char *sm_username(uid_t uid, char *buf, size_t buflen)
{
    struct passwd *pw;
    if (uid == (uid_t)-1) {
        snprintf(buf, buflen, "?");
        return buf;
    }
    pw = getpwuid(uid);
    if (pw && pw->pw_name)
        snprintf(buf, buflen, "%s", pw->pw_name);
    else
        snprintf(buf, buflen, "%u", (unsigned)uid);
    return buf;
}

/* MemTotal in bytes for the mem% denominator. */
static uint64_t sm_mem_total_bytes(void)
{
    char buf[4096];
    char *p;
    if (sm_read_file("/proc/meminfo", buf, sizeof(buf)) < 0)
        return 0;
    p = strstr(buf, "MemTotal:");
    if (!p)
        return 0;
    p += 9;
    while (*p == ' ' || *p == '\t')
        p++;
    return strtoull(p, NULL, 10) * 1024; /* kB -> bytes */
}

/* Sort helpers: descending by the chosen key. */
struct sm_proc_row {
    struct sm_proc p;
    double cpu_percent;
    double mem_percent;
};

static int g_sm_sort_by_mem;
static int sm_proc_cmp(const void *a, const void *b)
{
    const struct sm_proc_row *ra = a, *rb = b;
    double va = g_sm_sort_by_mem ? ra->mem_percent : ra->cpu_percent;
    double vb = g_sm_sort_by_mem ? rb->mem_percent : rb->cpu_percent;
    if (va < vb) return 1;
    if (va > vb) return -1;
    /* tiebreak by RSS then pid for stable ordering */
    if (ra->p.rss_bytes != rb->p.rss_bytes)
        return ra->p.rss_bytes < rb->p.rss_bytes ? 1 : -1;
    return ra->p.pid - rb->p.pid;
}

static struct json_object *sm_processes_data(struct jmx_api_ctx *ctx)
{
    struct json_object *data = json_object_new_object();
    struct json_object *arr = json_object_new_array();
    struct sm_proc *snap1 = NULL, *snap2 = NULL;
    struct sm_proc_row *rows = NULL;
    struct sm_cpu_times agg1, agg2, dummy[1];
    int n1, n2, nrow = 0, i, interval, limit, sort_by_mem = 0;
    int ncpu;
    uint64_t total_delta, mem_total;
    char raw[16] = "";

    interval = sm_sample_interval(ctx);
    ncpu = (int)sysconf(_SC_NPROCESSORS_ONLN);
    if (ncpu < 1) ncpu = 1;
    mem_total = sm_mem_total_bytes();

    if (ctx && ctx->req &&
        webd_query_get(ctx->req->query, "sort", raw, sizeof(raw)) == 0 &&
        !strcmp(raw, "mem"))
        sort_by_mem = 1;
    limit = SM_PROC_RETURN_DEFAULT;
    raw[0] = '\0';
    if (ctx && ctx->req &&
        webd_query_get(ctx->req->query, "limit", raw, sizeof(raw)) == 0 && raw[0]) {
        int v = atoi(raw);
        if (v > 0) limit = v;
    }
    if (limit > SM_PROC_RETURN_MAX) limit = SM_PROC_RETURN_MAX;

    snap1 = calloc(SM_PROC_SCAN_MAX, sizeof(*snap1));
    snap2 = calloc(SM_PROC_SCAN_MAX, sizeof(*snap2));
    if (!snap1 || !snap2) {
        free(snap1); free(snap2); json_object_put(arr);
        json_object_object_add(data, "available", json_object_new_boolean(0));
        json_object_object_add(data, "reason", json_object_new_string("out_of_memory"));
        return data;
    }

    (void)sm_read_cpu_snapshot(&agg1, dummy, 0);
    n1 = sm_read_proc_snapshot(snap1, SM_PROC_SCAN_MAX);
    sm_sleep_ms(interval);
    (void)sm_read_cpu_snapshot(&agg2, dummy, 0);
    n2 = sm_read_proc_snapshot(snap2, SM_PROC_SCAN_MAX);
    if (n1 < 0) n1 = 0;
    if (n2 < 0) n2 = 0;
    total_delta = (agg2.total >= agg1.total) ? agg2.total - agg1.total : 0;

    rows = calloc(n2 > 0 ? n2 : 1, sizeof(*rows));
    if (!rows) {
        free(snap1); free(snap2); json_object_put(arr);
        json_object_object_add(data, "available", json_object_new_boolean(0));
        json_object_object_add(data, "reason", json_object_new_string("out_of_memory"));
        return data;
    }

    /* CPU% per pid: (Δjiffies / Δtotal_jiffies) * ncpu * 100, matched by pid. */
    for (i = 0; i < n2; i++) {
        struct sm_proc *cur = &snap2[i];
        uint64_t prev_j = 0;
        int found = 0, j;
        double cpu = 0.0, mem = 0.0;

        for (j = 0; j < n1; j++) {
            if (snap1[j].pid == cur->pid) { prev_j = snap1[j].jiffies; found = 1; break; }
        }
        if (found && total_delta > 0 && cur->jiffies >= prev_j) {
            cpu = (double)(cur->jiffies - prev_j) * 100.0 * (double)ncpu / (double)total_delta;
            if (cpu < 0) cpu = 0;
            if (cpu > 100.0 * ncpu) cpu = 100.0 * ncpu;
        }
        if (mem_total > 0)
            mem = (double)cur->rss_bytes * 100.0 / (double)mem_total;
        rows[nrow].p = *cur;
        rows[nrow].cpu_percent = cpu;
        rows[nrow].mem_percent = mem;
        nrow++;
    }

    g_sm_sort_by_mem = sort_by_mem;
    qsort(rows, nrow, sizeof(*rows), sm_proc_cmp);

    json_object_object_add(data, "available", json_object_new_boolean(1));
    for (i = 0; i < nrow && i < limit; i++) {
        struct json_object *o = json_object_new_object();
        struct sm_proc *p = &rows[i].p;
        char user[64], cmdline[1024];
        char stbuf[2] = { p->state, '\0' };

        sm_username(p->uid, user, sizeof(user));
        sm_read_cmdline(p->pid, cmdline, sizeof(cmdline));
        if (!cmdline[0])
            snprintf(cmdline, sizeof(cmdline), "[%s]", p->comm);

        json_object_object_add(o, "pid", json_object_new_int(p->pid));
        json_object_object_add(o, "ppid", json_object_new_int(p->ppid));
        json_object_object_add(o, "name", json_object_new_string(p->comm));
        json_object_object_add(o, "user", json_object_new_string(user));
        json_object_object_add(o, "cpu_percent",
                               json_object_new_double(sm_round1(rows[i].cpu_percent)));
        json_object_object_add(o, "mem_percent",
                               json_object_new_double(sm_round1(rows[i].mem_percent)));
        json_object_object_add(o, "rss_bytes", json_object_new_int64((int64_t)p->rss_bytes));
        json_object_object_add(o, "state", json_object_new_string(stbuf));
        json_object_object_add(o, "threads", json_object_new_int(p->threads));
        json_object_object_add(o, "cmdline", json_object_new_string(cmdline));
        json_object_array_add(arr, o);
    }
    json_object_object_add(data, "processes", arr);
    json_object_object_add(data, "process_count", json_object_new_int(nrow));
    json_object_object_add(data, "returned", json_object_new_int(i));
    json_object_object_add(data, "sort", json_object_new_string(sort_by_mem ? "mem" : "cpu"));
    json_object_object_add(data, "sample_interval_ms", json_object_new_int(interval));
    json_object_object_add(data, "ncpu", json_object_new_int(ncpu));
    json_object_object_add(data, "mem_total_bytes", json_object_new_int64((int64_t)mem_total));

    free(snap1);
    free(snap2);
    free(rows);
    return data;
}

static struct json_object *sm_handle_processes(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = sm_envelope(sm_processes_data(ctx),
                                           "webd.system_monitor.processes");
    ctx->status = 200;
    return resp;
}

/* ── startup items (read-only) ──────────────────────────────────────────── */

/* Same token discipline core uses: init-script names are [A-Za-z0-9_-]. */
static int sm_initd_token_ok(const char *name)
{
    const unsigned char *p;
    if (!name || !name[0])
        return 0;
    for (p = (const unsigned char *)name; *p; p++)
        if (!isalnum(*p) && *p != '_' && *p != '-')
            return 0;
    return 1;
}

/* Enabled = an /etc/rc.d/S??<name> symlink exists. start_order is the NN in
 * S<NN><name>. Returns 1 enabled (order into *order), 0 disabled. This is a
 * pure readdir of /etc/rc.d, no exec of the init script. */
static int sm_initd_enabled(const char *name, int *order)
{
    DIR *d = opendir(SM_RCD_DIR);
    struct dirent *e;
    int enabled = 0;

    *order = -1;
    if (!d)
        return 0;
    while ((e = readdir(d)) != NULL) {
        const char *n = e->d_name;
        if (n[0] != 'S')
            continue;
        if (!isdigit((unsigned char)n[1]) || !isdigit((unsigned char)n[2]))
            continue;
        if (!strcmp(n + 3, name)) {
            enabled = 1;
            *order = (n[1] - '0') * 10 + (n[2] - '0');
            break;
        }
    }
    closedir(d);
    return enabled;
}

/* First "# " comment line inside an init script, as a rough description. */
static void sm_initd_description(const char *name, char *out, size_t outlen)
{
    char path[128], buf[2048];
    char *line, *save;

    out[0] = '\0';
    if (snprintf(path, sizeof(path), SM_INITD_DIR "/%s", name) >= (int)sizeof(path))
        return;
    if (sm_read_file(path, buf, sizeof(buf)) <= 0)
        return;
    line = strtok_r(buf, "\n", &save);
    while (line) {
        /* skip shebang and USE_PROCD/START lines; grab a descriptive comment */
        if (line[0] == '#' && line[1] == ' ' && strlen(line) > 4 &&
            !strstr(line, "SPDX") && !strstr(line, "Copyright") &&
            !strstr(line, "/bin/sh")) {
            snprintf(out, outlen, "%s", line + 2);
            return;
        }
        line = strtok_r(NULL, "\n", &save);
    }
}

static int sm_startup_name_cmp(const void *a, const void *b)
{
    /* qsort elements are char[64] buffers, so a/b point straight at the name
     * bytes -- NOT at a char* to dereference. Reading them as pointers segfaults
     * on the first name (fault addr == the name's own bytes). */
    return strcmp((const char *)a, (const char *)b);
}

static struct json_object *sm_startup_data(void)
{
    struct json_object *data = json_object_new_object();
    struct json_object *arr = json_object_new_array();
    DIR *d = opendir(SM_INITD_DIR);
    struct dirent *e;
    char (*names)[64] = NULL;
    int count = 0, i, truncated = 0;

    if (!d) {
        json_object_put(arr);
        json_object_object_add(data, "available", json_object_new_boolean(0));
        json_object_object_add(data, "reason", json_object_new_string("initd_dir_unavailable"));
        return data;
    }
    names = calloc(SM_INITD_MAX, sizeof(*names));
    if (!names) {
        closedir(d);
        json_object_put(arr);
        json_object_object_add(data, "available", json_object_new_boolean(0));
        json_object_object_add(data, "reason", json_object_new_string("out_of_memory"));
        return data;
    }
    while ((e = readdir(d)) != NULL) {
        char path[128];
        struct stat st;
        if (!sm_initd_token_ok(e->d_name))
            continue;
        if (count >= SM_INITD_MAX) { truncated = 1; break; }
        if (snprintf(path, sizeof(path), SM_INITD_DIR "/%s", e->d_name) >= (int)sizeof(path))
            continue;
        /* only regular executable files */
        if (stat(path, &st) != 0 || !S_ISREG(st.st_mode) ||
            (st.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH)) == 0)
            continue;
        if (JMX_STRBUF_COPY(names[count], e->d_name) != 0) {
            truncated = 1;
            continue;
        }
        count++;
    }
    closedir(d);
    qsort(names, count, sizeof(*names), sm_startup_name_cmp);

    json_object_object_add(data, "available", json_object_new_boolean(1));
    for (i = 0; i < count; i++) {
        struct json_object *o = json_object_new_object();
        int order = -1;
        int enabled = sm_initd_enabled(names[i], &order);
        char desc[256];

        sm_initd_description(names[i], desc, sizeof(desc));
        json_object_object_add(o, "name", json_object_new_string(names[i]));
        json_object_object_add(o, "enabled", json_object_new_boolean(enabled));
        json_object_object_add(o, "start_order", json_object_new_int(order));
        json_object_object_add(o, "description", json_object_new_string(desc));
        json_object_array_add(arr, o);
    }
    json_object_object_add(data, "items", arr);
    json_object_object_add(data, "count", json_object_new_int(count));
    json_object_object_add(data, "truncated", json_object_new_boolean(truncated));
    /* toggling (enable/disable) is a write; frontend routes it through the
     * existing core action, not this read view. */
    json_object_object_add(data, "toggle_via",
                           json_object_new_string("/api/v1/system/startup/service-action"));
    free(names);
    return data;
}

static struct json_object *sm_handle_startup(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = sm_envelope(sm_startup_data(),
                                           "webd.system_monitor.startup");
    ctx->status = 200;
    return resp;
}

/* ── process signal (WRITE, admin-only via risk table) ──────────────────── */

static int sm_signal_from_name(const char *name)
{
    size_t i;
    if (!name || !name[0])
        return -1;
    for (i = 0; i < sizeof(sm_allowed_signals) / sizeof(sm_allowed_signals[0]); i++)
        if (!strcmp(name, sm_allowed_signals[i].name))
            return sm_allowed_signals[i].sig;
    return -1;
}

/* Read /proc/<pid>/stat comm for the protected-name check. */
static int sm_proc_comm(int pid, char *out, size_t outlen)
{
    char path[64], buf[4096];
    const char *lp, *rp;
    size_t len;

    out[0] = '\0';
    snprintf(path, sizeof(path), "/proc/%d/stat", pid);
    if (sm_read_file(path, buf, sizeof(buf)) < 0)
        return -1;
    lp = strchr(buf, '(');
    rp = lp ? strrchr(lp, ')') : NULL;
    if (!lp || !rp)
        return -1;
    len = (size_t)(rp - (lp + 1));
    if (len >= outlen)
        len = outlen - 1;
    memcpy(out, lp + 1, len);
    out[len] = '\0';
    return 0;
}

static int sm_comm_is_protected(const char *comm)
{
    size_t i;
    for (i = 0; i < sizeof(sm_protected_comm) / sizeof(sm_protected_comm[0]); i++)
        if (!strcmp(comm, sm_protected_comm[i]))
            return 1;
    return 0;
}

/* Extract the pid from exactly /api/v1/system/processes/<digits>/signal.
 * Any other shape under the prefix (extra segments, non-digit id, missing
 * /signal suffix) returns -1 so the write cannot be reached by a stray path. */
static int sm_pid_from_path(const char *path)
{
    const char *prefix = "/api/v1/system/processes/";
    size_t plen = strlen(prefix);
    const char *p, *seg_end;
    long pid;

    if (strncmp(path, prefix, plen) != 0)
        return -1;
    p = path + plen;
    if (*p < '0' || *p > '9')
        return -1;
    pid = strtol(p, (char **)&seg_end, 10);
    if (seg_end == p || strcmp(seg_end, "/signal") != 0)
        return -1;
    if (pid <= 0 || pid > INT_MAX)
        return -1;
    return (int)pid;
}

static struct json_object *sm_signal_error(struct jmx_api_ctx *ctx, int http,
                                           const char *code, const char *msg)
{
    ctx->status = http;
    return webd_error(code, msg, "", "webd.system_monitor.signal");
}

static struct json_object *sm_handle_process_signal(struct jmx_api_ctx *ctx)
{
    int pid, sig;
    const char *signame;
    char comm[32] = "";
    struct json_object *resp, *data;

    if (!ctx || !ctx->req)
        return sm_signal_error(ctx, 500, "internal_error", "no request context");

    pid = sm_pid_from_path(ctx->req->path);
    if (pid <= 1)
        return sm_signal_error(ctx, 400, "invalid_pid",
                               "pid must be a positive integer greater than 1");

    signame = app_nc_json_str(ctx->body, "signal", "TERM");
    sig = sm_signal_from_name(signame);
    if (sig < 0)
        return sm_signal_error(ctx, 400, "invalid_signal",
                               "signal must be one of TERM,KILL,HUP,INT,QUIT,USR1,USR2,STOP,CONT");

    /* Never signal our own process group's supervisor chain or the pool. */
    if (pid == 1 || (pid_t)pid == getpid() || (pid_t)pid == getppid())
        return sm_signal_error(ctx, 403, "protected_process",
                               "refusing to signal a supervisor/self process");

    if (sm_proc_comm(pid, comm, sizeof(comm)) != 0)
        return sm_signal_error(ctx, 404, "process_not_found", "no such pid");

    if (sm_comm_is_protected(comm)) {
        struct json_object *e = sm_signal_error(ctx, 403, "protected_process",
            "this process is protected; signalling it could drop the control plane, network, or admin UI");
        return e;
    }

    errno = 0;
    if (kill((pid_t)pid, sig) != 0) {
        int err = errno;
        if (err == ESRCH)
            return sm_signal_error(ctx, 404, "process_not_found", "no such pid");
        if (err == EPERM)
            return sm_signal_error(ctx, 403, "permission_denied", "kill refused by kernel");
        return sm_signal_error(ctx, 500, "signal_failed", strerror(err));
    }

    {
        char target[64];
        snprintf(target, sizeof(target), "pid=%d(%s)", pid, comm);
        jmx_app_audit_log(ctx->device_id && ctx->device_id[0] ? ctx->device_id : "web",
                          ctx->device_id ? ctx->device_id : "",
                          "system.process.signal", "high", target, "", signame);
    }

    data = json_object_new_object();
    json_object_object_add(data, "pid", json_object_new_int(pid));
    json_object_object_add(data, "name", json_object_new_string(comm));
    json_object_object_add(data, "signal", json_object_new_string(signame));
    json_object_object_add(data, "delivered", json_object_new_boolean(1));
    resp = sm_envelope(data, "webd.system_monitor.signal");
    ctx->status = 200;
    return resp;
}

/* ── route table ────────────────────────────────────────────────────────── */

/* original_seq is the logical dispatch position the route-inventory extractor
 * orders by; it must be a unique positive integer (merge_routes rejects < 1 and
 * parse_table_routes rejects duplicates). These are all-new routes that never
 * lived in the legacy chain, so they append after the current maximum — 900/901
 * belong to api_audit_log, so this module takes 902-906. The signal route is a
 * PREFIX so the /<pid>/signal suffix matches; risk is set to HIGH in
 * g_route_risks so viewer is refused and only admin can deliver a signal. */
const struct jmx_api_route system_monitor_api_routes[] = {
    JMX_API_ROUTE(902, "/api/v1/system/processes", "GET", JMX_API_EXACT, sm_handle_processes),
    JMX_API_ROUTE(903, "/api/v1/system/cpu",       "GET", JMX_API_EXACT, sm_handle_cpu),
    JMX_API_ROUTE(904, "/api/v1/system/interfaces","GET", JMX_API_EXACT, sm_handle_interfaces),
    JMX_API_ROUTE(905, "/api/v1/system/startup",   "GET", JMX_API_EXACT, sm_handle_startup),
    JMX_API_ROUTE(906, "/api/v1/system/processes/","POST,PUT", JMX_API_PREFIX, sm_handle_process_signal),
    JMX_API_ROUTE_END,
};

