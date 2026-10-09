// SPDX-License-Identifier: GPL-2.0-or-later
#include "flowd_tc_apply.h"
#include "flowd_runtime_contract.h"
#include "flowd_wan_runtime.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <net/if.h>

#define FLOWD_TC_MAX_PROFILES 64
#define FLOWD_TC_MAX_CLASSES 64
#define FLOWD_TC_OUTPUT_MAX (256U * 1024U)
#define FLOWD_TC_TIMEOUT_MS 5000

struct flowd_tc_profile {
    char id[FLOWD_MAX_ID];
    char wan[128];
    char ifname[IFNAMSIZ];
    char scheduler[32];
    int64_t down_kbps;
    int64_t up_kbps;
    int headroom_pct;
    int ingress;
    int egress;
};

struct flowd_tc_class {
    char id[FLOWD_MAX_ID];
    int guarantee_pct;
    int ceiling_pct;
};

struct flowd_tc_plan {
    struct flowd_tc_profile profiles[FLOWD_TC_MAX_PROFILES];
    size_t profile_count;
    struct flowd_tc_class classes[FLOWD_TC_MAX_CLASSES];
    size_t class_count;
    int qos_enabled;
    int qos_diffserv;
    int qos_ack_filter;
    char qos_scheduler[32];
    char qos_fairness[32];
};

struct flowd_tc_capture {
    char *data;
    size_t len;
};

struct flowd_tc_qdisc_state {
    char kind[32];
    char diffserv[32];
    int64_t bandwidth_bytes;
};

static int64_t flowd_tc_now_ms(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return -1;
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static int flowd_tc_token_ok(const char *s, size_t max_len)
{
    const unsigned char *p;

    if (!s || !s[0] || strlen(s) > max_len)
        return 0;
    for (p = (const unsigned char *)s; *p; p++) {
        if (!(isalnum(*p) || *p == '-' || *p == '_' || *p == '.' || *p == ':'))
            return 0;
    }
    return 1;
}

static int flowd_tc_ifb_name(const char *wan, char *out, size_t out_len)
{
    uint32_t hash = 2166136261U;
    const unsigned char *p;

    if (!wan || !out || out_len == 0)
        return -1;
    for (p = (const unsigned char *)wan; *p; p++)
        hash = (hash ^ *p) * 16777619U;
    if (snprintf(out, out_len, "ifb-fd-%04x", hash & 0xffffU) >= (int)out_len)
        return -1;
    return 0;
}

static int flowd_tc_capture_append(struct flowd_tc_capture *capture,
                                   const char *data, size_t len)
{
    size_t keep;
    char *next;

    if (!capture || !data || len == 0)
        return 0;
    keep = len;
    if (capture->len >= FLOWD_TC_OUTPUT_MAX)
        return -1;
    if (keep > FLOWD_TC_OUTPUT_MAX - capture->len)
        keep = FLOWD_TC_OUTPUT_MAX - capture->len;
    next = realloc(capture->data, capture->len + keep + 1);
    if (!next)
        return -1;
    memcpy(next + capture->len, data, keep);
    capture->len += keep;
    next[capture->len] = '\0';
    capture->data = next;
    return keep == len ? 0 : -1;
}

static int flowd_tc_run(char *const argv[], struct flowd_tc_capture *capture)
{
    int pipefd[2] = { -1, -1 };
    pid_t pid;
    int status = 0;
    int done = 0;
    int64_t deadline;
    struct pollfd pfd;
    char buf[4096];

    if (!argv || !argv[0] || !capture)
        return -1;
    memset(capture, 0, sizeof(*capture));
    deadline = flowd_tc_now_ms();
    if (deadline < 0 || pipe(pipefd) != 0)
        return -1;
    deadline += FLOWD_TC_TIMEOUT_MS;
    pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }
    if (pid == 0) {
        close(pipefd[0]);
        if (dup2(pipefd[1], STDOUT_FILENO) < 0 ||
            dup2(pipefd[1], STDERR_FILENO) < 0)
            _exit(126);
        close(pipefd[1]);
        execv(argv[0], argv);
        _exit(127);
    }
    close(pipefd[1]);
    pipefd[1] = -1;
    fcntl(pipefd[0], F_SETFL, fcntl(pipefd[0], F_GETFL, 0) | O_NONBLOCK);
    pfd.fd = pipefd[0];
    pfd.events = POLLIN | POLLHUP;
    while (!done) {
        ssize_t n;
        int64_t now;
        pid_t wait_rc;

        while ((n = read(pipefd[0], buf, sizeof(buf))) > 0) {
            if (flowd_tc_capture_append(capture, buf, (size_t)n) != 0) {
                kill(pid, SIGTERM);
                waitpid(pid, &status, 0);
                close(pipefd[0]);
                free(capture->data);
                capture->data = NULL;
                capture->len = 0;
                return -2;
            }
        }
        wait_rc = waitpid(pid, &status, WNOHANG);
        if (wait_rc == pid)
            done = 1;
        else if (wait_rc < 0 && errno != EINTR) {
            kill(pid, SIGTERM);
            waitpid(pid, &status, 0);
            close(pipefd[0]);
            free(capture->data);
            capture->data = NULL;
            capture->len = 0;
            return -1;
        }
        now = flowd_tc_now_ms();
        if (!done && (now < 0 || now >= deadline)) {
            kill(pid, SIGTERM);
            waitpid(pid, &status, 0);
            close(pipefd[0]);
            free(capture->data);
            capture->data = NULL;
            capture->len = 0;
            return -3;
        }
        if (!done)
            poll(&pfd, 1, 20);
    }
    while (read(pipefd[0], buf, sizeof(buf)) > 0)
        ;
    close(pipefd[0]);
    if (!WIFEXITED(status))
        return -1;
    return WEXITSTATUS(status);
}

static int flowd_tc_json_root_state(const char *text,
                                    struct flowd_tc_qdisc_state *state)
{
    struct json_object *root = NULL;
    struct json_object *entry = NULL;
    struct json_object *items = NULL;
    struct json_object *value = NULL;
    size_t i;
    int found = 0;

    if (!text || !state)
        return -1;
    memset(state, 0, sizeof(*state));
    root = json_tokener_parse(text);
    if (!root) {
        json_object_put(root);
        return -1;
    }
    if (json_object_is_type(root, json_type_array)) {
        items = root;
    } else if (!json_object_object_get_ex(root, "qdisc", &items) ||
               !json_object_is_type(items, json_type_array)) {
        json_object_put(root);
        return -1;
    }
    for (i = 0; i < json_object_array_length(items); i++) {
        entry = json_object_array_get_idx(items, i);
        if (!entry || !json_object_object_get_ex(entry, "root", &value) ||
            !json_object_get_boolean(value))
            continue;
        if (!json_object_object_get_ex(entry, "kind", &value))
            continue;
        snprintf(state->kind, sizeof(state->kind), "%s",
                 json_object_get_string(value));
        if (json_object_object_get_ex(entry, "options", &value) &&
            value && json_object_is_type(value, json_type_object)) {
            struct json_object *option = NULL;

            if (json_object_object_get_ex(value, "bandwidth", &option) && option)
                state->bandwidth_bytes = json_object_get_int64(option);
            if (json_object_object_get_ex(value, "diffserv", &option) && option &&
                json_object_is_type(option, json_type_string))
                snprintf(state->diffserv, sizeof(state->diffserv), "%s",
                         json_object_get_string(option));
        }
        found = 1;
        break;
    }
    json_object_put(root);
    return found ? 0 : -1;
}

static int flowd_tc_qdisc_state(const char *ifname,
                                struct flowd_tc_qdisc_state *state)
{
    char *argv[] = { (char *)FLOWD_TC_BINARY, "-j", "-d", "qdisc", "show", "dev",
                     (char *)ifname, NULL };
    struct flowd_tc_capture capture;
    int rc;

    rc = flowd_tc_run(argv, &capture);
    if (rc == 0)
        rc = flowd_tc_json_root_state(capture.data, state);
    free(capture.data);
    return rc;
}

static int flowd_tc_qdisc_kind(const char *ifname, char *kind, size_t kind_len)
{
    struct flowd_tc_qdisc_state state;
    int rc;

    if (!kind || kind_len == 0)
        return -1;
    kind[0] = '\0';
    rc = flowd_tc_qdisc_state(ifname, &state);
    if (rc == 0)
        snprintf(kind, kind_len, "%s", state.kind);
    return rc;
}

static int flowd_tc_command(char *const argv[])
{
    struct flowd_tc_capture capture;
    int rc = flowd_tc_run(argv, &capture);

    free(capture.data);
    return rc;
}

static int flowd_tc_rate(int64_t raw, int headroom_pct)
{
    int64_t value = raw * headroom_pct / 100;

    if (value < 1)
        value = 1;
    if (value > 100000000)
        value = 100000000;
    return (int)value;
}

static int64_t flowd_tc_json_int64(struct json_object *object, const char *key)
{
    struct json_object *value = NULL;

    if (!object || !key || !json_object_object_get_ex(object, key, &value) || !value)
        return 0;
    return json_object_get_int64(value);
}

static int flowd_tc_classid(const char *id, unsigned int *out)
{
    uint32_t hash = 2166136261U;
    const unsigned char *p;

    if (!id || !out)
        return -1;
    for (p = (const unsigned char *)id; *p; p++)
        hash = (hash ^ *p) * 16777619U;
    *out = 10U + (hash % 60000U);
    return 0;
}

static int flowd_tc_apply_qdisc(const char *ifname, const char *scheduler,
                                int rate_kbps, int qos_enabled,
                                int qos_diffserv, int qos_ack_filter,
                                const char *qos_fairness,
                                const struct flowd_tc_class *classes,
                                size_t class_count)
{
    char rate[32];
    char classid[32];
    size_t i;
    char *argv[16];
    unsigned int id;

    if (!flowd_tc_token_ok(ifname, 15) || !scheduler)
        return -1;
    if (!strcmp(scheduler, "none")) {
        char *del[] = { (char *)FLOWD_TC_BINARY, "qdisc", "del", "dev",
                        (char *)ifname, "root", NULL };
        if (flowd_tc_command(del) != 0) {
            char kind[32] = "";
            if (flowd_tc_qdisc_kind(ifname, kind, sizeof(kind)) == 0 &&
                strcmp(kind, "noqueue"))
                return -1;
        }
        return 0;
    }
    if (rate_kbps < 1)
        return -1;
    snprintf(rate, sizeof(rate), "%dkbit", rate_kbps);
    if (!strcmp(scheduler, "cake")) {
        const char *diffserv = qos_enabled && qos_diffserv ? "diffserv4" : "besteffort";
        const char *flowmode = !qos_enabled || !qos_fairness ||
                               !strcmp(qos_fairness, "per_host")
            ? "triple-isolate" :
              (!strcmp(qos_fairness, "none") ? "flowblind" : "flows");
        char *cake[] = { (char *)FLOWD_TC_BINARY, "qdisc", "replace", "dev",
                         (char *)ifname, "root", "cake", "bandwidth", rate,
                         (char *)diffserv, (char *)flowmode,
                         (char *)(qos_enabled && qos_ack_filter ? "ack-filter" :
                                  "no-ack-filter"), NULL };

        (void)classes;
        (void)class_count;
        return flowd_tc_command(cake);
    }
    if (!strcmp(scheduler, "fq_codel")) {
        char *fq[] = { (char *)FLOWD_TC_BINARY, "qdisc", "replace", "dev",
                       (char *)ifname, "root", "fq_codel", NULL };
        if (qos_enabled && class_count > 0)
            return -2;
        return flowd_tc_command(fq);
    }
    if (strcmp(scheduler, "htb"))
        return -2;
    argv[0] = (char *)FLOWD_TC_BINARY;
    argv[1] = "qdisc";
    argv[2] = "replace";
    argv[3] = "dev";
    argv[4] = (char *)ifname;
    argv[5] = "root";
    argv[6] = "handle";
    argv[7] = "1:";
    argv[8] = "htb";
    argv[9] = "default";
    argv[10] = "999";
    argv[11] = NULL;
    if (flowd_tc_command(argv) != 0)
        return -1;
    snprintf(classid, sizeof(classid), "1:1");
    {
        char *default_class[] = { (char *)FLOWD_TC_BINARY, "class", "replace", "dev",
                                  (char *)ifname, "parent", "1:", "classid", classid,
                                  "htb", "rate", rate, "ceil", rate, NULL };
        if (flowd_tc_command(default_class) != 0)
            return -1;
    }
    snprintf(classid, sizeof(classid), "1:999");
    {
        char *fallback_class[] = { (char *)FLOWD_TC_BINARY, "class", "replace", "dev",
                                   (char *)ifname, "parent", "1:1", "classid", classid,
                                   "htb", "rate", rate, "ceil", rate, NULL };
        if (flowd_tc_command(fallback_class) != 0)
            return -1;
    }
    if (!qos_enabled)
        return 0;
    for (i = 0; i < class_count; i++) {
        int class_rate = rate_kbps * classes[i].guarantee_pct / 100;
        int class_ceil = rate_kbps * classes[i].ceiling_pct / 100;

        if (class_rate < 1)
            class_rate = 1;
        if (class_ceil < class_rate)
            class_ceil = class_rate;
        if (flowd_tc_classid(classes[i].id, &id) != 0)
            return -1;
        snprintf(classid, sizeof(classid), "1:%u", id);
        snprintf(rate, sizeof(rate), "%dkbit", class_rate);
        {
            char ceil[32];
            char *class_argv[] = { (char *)FLOWD_TC_BINARY, "class", "replace", "dev",
                                   (char *)ifname, "parent", "1:", "classid", classid,
                                   "htb", "rate", rate, "ceil", ceil, NULL };
            snprintf(ceil, sizeof(ceil), "%dkbit", class_ceil);
            if (flowd_tc_command(class_argv) != 0)
                return -1;
        }
    }
    return 0;
}

static int flowd_tc_ifb_prepare(const char *ifb)
{
    char *add[] = { (char *)FLOWD_IP_BINARY, "link", "add", (char *)ifb,
                    "type", "ifb", NULL };
    char *up[] = { (char *)FLOWD_IP_BINARY, "link", "set", "dev", (char *)ifb,
                   "up", NULL };
    char *kind[] = { (char *)FLOWD_TC_BINARY, "qdisc", "show", "dev", (char *)ifb, NULL };

    if (flowd_tc_command(add) != 0) {
        struct flowd_tc_capture capture;
        if (flowd_tc_run(kind, &capture) != 0) {
            free(capture.data);
            return -1;
        }
        free(capture.data);
    }
    return flowd_tc_command(up);
}

static int flowd_tc_ingress_attach(const char *wan, const char *ifb)
{
    char *qdisc[] = { (char *)FLOWD_TC_BINARY, "qdisc", "replace", "dev",
                      (char *)wan, "handle", "ffff:", "ingress", NULL };
    char *filter[] = { (char *)FLOWD_TC_BINARY, "filter", "replace", "dev",
                       (char *)wan, "parent", "ffff:", "protocol", "all",
                       "pref", "49152", "matchall", "action", "mirred",
                       "egress", "redirect", "dev", (char *)ifb, NULL };

    return flowd_tc_command(qdisc) == 0 && flowd_tc_command(filter) == 0 ? 0 : -1;
}

static void flowd_tc_ingress_clear(const char *wan, const char *ifb)
{
    char *qdisc[] = { (char *)FLOWD_TC_BINARY, "qdisc", "del", "dev",
                      (char *)wan, "ingress", NULL };
    char *del[] = { (char *)FLOWD_IP_BINARY, "link", "del", (char *)ifb, NULL };

    flowd_tc_command(qdisc);
    flowd_tc_command(del);
}

static int flowd_tc_profile_kind(const char *scheduler, char *kind, size_t kind_len)
{
    if (!scheduler || !kind || kind_len == 0)
        return -1;
    if (!strcmp(scheduler, "none"))
        snprintf(kind, kind_len, "noqueue");
    else
        snprintf(kind, kind_len, "%s", scheduler);
    return 0;
}

static int flowd_tc_read_profile(struct json_object *o, struct flowd_tc_profile *p)
{
    const char *s;

    if (!o || !p)
        return -1;
    memset(p, 0, sizeof(*p));
    s = flowd_json_str(o, "id", "");
    if (!flowd_id_ok(s))
        return -1;
    snprintf(p->id, sizeof(p->id), "%s", s);
    s = flowd_json_str(o, "wan", "");
    if (!flowd_tc_token_ok(s, 15))
        return -1;
    snprintf(p->wan, sizeof(p->wan), "%s", s);
    s = flowd_json_str(o, "ifname", "");
    if (s[0] && flowd_tc_token_ok(s, IFNAMSIZ - 1) && if_nametoindex(s))
        snprintf(p->ifname, sizeof(p->ifname), "%s", s);
    else if (flowd_wan_resolve_ifname(p->wan, p->ifname,
                                      sizeof(p->ifname)) != 0)
            return -1;
    s = flowd_json_str(o, "scheduler", "none");
    snprintf(p->scheduler, sizeof(p->scheduler), "%s", s);
    p->down_kbps = flowd_tc_json_int64(o, "down_kbps");
    p->up_kbps = flowd_tc_json_int64(o, "up_kbps");
    p->headroom_pct = flowd_json_int(o, "headroom_pct", 95);
    p->ingress = flowd_json_bool(o, "ingress", 0);
    p->egress = flowd_json_bool(o, "egress", 1);
    return p->headroom_pct >= 50 && p->headroom_pct <= 100 ? 0 : -1;
}

static struct json_object *flowd_tc_plan_from_config(void)
{
    struct json_object *plan = json_object_new_object();
    struct json_object *profiles = json_object_new_array();
    struct json_object *classes = json_object_new_array();
    struct json_object *qos = json_object_new_object();
    sqlite3_stmt *st;

    st = flowd_config_prepare(
        "SELECT id,wan,down_kbps,up_kbps,headroom_pct,scheduler,ingress,egress "
        "FROM flowd_wan_capacity WHERE enabled=1 ORDER BY wan,id");
    if (st) {
        while (sqlite3_step(st) == SQLITE_ROW) {
            struct json_object *o = json_object_new_object();
            char ifname[IFNAMSIZ] = "";

            json_object_object_add(o, "id", json_object_new_string(flowd_sqlite_text(st, 0, "")));
            json_object_object_add(o, "wan", json_object_new_string(flowd_sqlite_text(st, 1, "")));
            if (flowd_wan_resolve_ifname(flowd_sqlite_text(st, 1, ""), ifname,
                                         sizeof(ifname)) == 0)
                json_object_object_add(o, "ifname", json_object_new_string(ifname));
            json_object_object_add(o, "down_kbps", json_object_new_int64(sqlite3_column_int64(st, 2)));
            json_object_object_add(o, "up_kbps", json_object_new_int64(sqlite3_column_int64(st, 3)));
            json_object_object_add(o, "headroom_pct", json_object_new_int(sqlite3_column_int(st, 4)));
            json_object_object_add(o, "scheduler", json_object_new_string(flowd_sqlite_text(st, 5, "none")));
            json_object_object_add(o, "ingress", json_object_new_boolean(sqlite3_column_int(st, 6)));
            json_object_object_add(o, "egress", json_object_new_boolean(sqlite3_column_int(st, 7)));
            json_object_array_add(profiles, o);
        }
        sqlite3_finalize(st);
    }
    st = flowd_config_prepare(
        "SELECT enabled,scheduler,diffserv,ack_filter,fairness "
        "FROM flowd_qos_settings WHERE id=1");
    if (st && sqlite3_step(st) == SQLITE_ROW) {
        json_object_object_add(qos, "enabled", json_object_new_boolean(sqlite3_column_int(st, 0)));
        json_object_object_add(qos, "scheduler", json_object_new_string(flowd_sqlite_text(st, 1, "htb")));
        json_object_object_add(qos, "diffserv", json_object_new_boolean(sqlite3_column_int(st, 2)));
        json_object_object_add(qos, "ack_filter", json_object_new_boolean(sqlite3_column_int(st, 3)));
        json_object_object_add(qos, "fairness", json_object_new_string(flowd_sqlite_text(st, 4, "per_host")));
    } else {
        json_object_object_add(qos, "enabled", json_object_new_boolean(0));
        json_object_object_add(qos, "scheduler", json_object_new_string("htb"));
        json_object_object_add(qos, "diffserv", json_object_new_boolean(1));
        json_object_object_add(qos, "ack_filter", json_object_new_boolean(0));
        json_object_object_add(qos, "fairness", json_object_new_string("per_host"));
    }
    if (st)
        sqlite3_finalize(st);
    st = flowd_config_prepare(
        "SELECT id,guarantee_pct,ceiling_pct FROM flowd_qos_classes WHERE enabled=1 ORDER BY priority,id");
    if (st) {
        while (sqlite3_step(st) == SQLITE_ROW) {
            struct json_object *o = json_object_new_object();

            json_object_object_add(o, "id", json_object_new_string(flowd_sqlite_text(st, 0, "")));
            json_object_object_add(o, "guarantee_pct", json_object_new_int(sqlite3_column_int(st, 1)));
            json_object_object_add(o, "ceiling_pct", json_object_new_int(sqlite3_column_int(st, 2)));
            json_object_array_add(classes, o);
        }
        sqlite3_finalize(st);
    }
    json_object_object_add(plan, "profiles", profiles);
    json_object_object_add(plan, "qos", qos);
    json_object_object_add(plan, "classes", classes);
    return plan;
}

static int flowd_tc_plan_load(struct json_object *plan, struct flowd_tc_plan *out)
{
    struct json_object *profiles = NULL;
    struct json_object *classes = NULL;
    struct json_object *qos = NULL;
    size_t i;

    if (!plan || !out || !json_object_object_get_ex(plan, "profiles", &profiles) ||
        !json_object_is_type(profiles, json_type_array) ||
        !json_object_object_get_ex(plan, "classes", &classes) ||
        !json_object_is_type(classes, json_type_array) ||
        !json_object_object_get_ex(plan, "qos", &qos) ||
        !json_object_is_type(qos, json_type_object))
        return -1;
    memset(out, 0, sizeof(*out));
    out->qos_enabled = flowd_json_bool(qos, "enabled", 0);
    out->qos_diffserv = flowd_json_bool(qos, "diffserv", 1);
    out->qos_ack_filter = flowd_json_bool(qos, "ack_filter", 0);
    snprintf(out->qos_scheduler, sizeof(out->qos_scheduler), "%s",
             flowd_json_str(qos, "scheduler", "htb"));
    snprintf(out->qos_fairness, sizeof(out->qos_fairness), "%s",
             flowd_json_str(qos, "fairness", "per_host"));
    if (json_object_array_length(profiles) > FLOWD_TC_MAX_PROFILES ||
        json_object_array_length(classes) > FLOWD_TC_MAX_CLASSES)
        return -1;
    for (i = 0; i < json_object_array_length(profiles); i++)
        if (flowd_tc_read_profile(json_object_array_get_idx(profiles, i),
                                   &out->profiles[out->profile_count++]) != 0)
            return -1;
    for (i = 0; i < json_object_array_length(classes); i++) {
        struct json_object *o = json_object_array_get_idx(classes, i);
        const char *id = flowd_json_str(o, "id", "");

        if (!flowd_id_ok(id))
            return -1;
        snprintf(out->classes[out->class_count].id,
                 sizeof(out->classes[out->class_count].id), "%s", id);
        out->classes[out->class_count].guarantee_pct = flowd_json_int(o, "guarantee_pct", 0);
        out->classes[out->class_count].ceiling_pct = flowd_json_int(o, "ceiling_pct", 100);
        out->class_count++;
    }
    return 0;
}

static int flowd_tc_state_db(sqlite3 **out, int create)
{
    sqlite3 *db = NULL;
    int flags = create ? SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE : SQLITE_OPEN_READONLY;

    if (!out)
        return -1;
    *out = NULL;
    if (!create && access(FLOWD_DEFAULT_FLOW_DB_PATH, F_OK) != 0)
        return -1;
    if (sqlite3_open_v2(FLOWD_DEFAULT_FLOW_DB_PATH, &db, flags, NULL) != SQLITE_OK) {
        sqlite3_close(db);
        return -1;
    }
    sqlite3_busy_timeout(db, 1000);
    if (create) {
        if (sqlite3_exec(db,
            "CREATE TABLE IF NOT EXISTS flowd_tc_apply_state ("
            "id INTEGER PRIMARY KEY CHECK(id=1),owner TEXT NOT NULL,"
            "runtime_applied INTEGER NOT NULL,rollback_ok INTEGER NOT NULL,"
            "phase TEXT NOT NULL,reason TEXT NOT NULL,generation TEXT NOT NULL,"
            "applied_at INTEGER NOT NULL,desired_json TEXT NOT NULL,readback_json TEXT NOT NULL)",
            NULL, NULL, NULL) != SQLITE_OK ||
            sqlite3_exec(db,
            "CREATE TABLE IF NOT EXISTS flowd_tc_resources ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT,owner TEXT NOT NULL,"
            "wan TEXT NOT NULL,direction TEXT NOT NULL,ifname TEXT NOT NULL,"
            "ifb_name TEXT NOT NULL,qdisc_kind TEXT NOT NULL,readback_json TEXT NOT NULL)",
            NULL, NULL, NULL) != SQLITE_OK) {
            sqlite3_close(db);
            return -1;
        }
    }
    *out = db;
    return 0;
}

static int flowd_tc_state_read_db(sqlite3 *db, struct flowd_tc_runtime_state *state,
                                  char **desired, char **readback)
{
    sqlite3_stmt *st = NULL;
    int rc;

    if (state)
        memset(state, 0, sizeof(*state));
    if (desired)
        *desired = NULL;
    if (readback)
        *readback = NULL;
    if (!db || sqlite3_prepare_v2(db,
        "SELECT runtime_applied,rollback_ok,phase,reason,generation,applied_at,desired_json,readback_json "
        "FROM flowd_tc_apply_state WHERE id=1", -1, &st, NULL) != SQLITE_OK)
        return -1;
    rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) {
        if (state) {
            state->present = 1;
            state->runtime_applied = sqlite3_column_int(st, 0);
            state->rollback_ok = sqlite3_column_int(st, 1);
            snprintf(state->phase, sizeof(state->phase), "%s", flowd_sqlite_text(st, 2, ""));
            snprintf(state->reason, sizeof(state->reason), "%s", flowd_sqlite_text(st, 3, ""));
            snprintf(state->generation, sizeof(state->generation), "%s", flowd_sqlite_text(st, 4, ""));
            state->applied_at = sqlite3_column_int64(st, 5);
        }
        if (desired)
            *desired = strdup(flowd_sqlite_text(st, 6, "{}"));
        if (readback)
            *readback = strdup(flowd_sqlite_text(st, 7, "{}"));
    }
    sqlite3_finalize(st);
    return rc == SQLITE_ROW ? 0 : -1;
}

int flowd_tc_runtime_state_read(struct flowd_tc_runtime_state *out)
{
    sqlite3 *db = NULL;
    int rc;

    if (!out || flowd_tc_state_db(&db, 0) != 0)
        return -1;
    rc = flowd_tc_state_read_db(db, out, NULL, NULL);
    sqlite3_close(db);
    return rc;
}

int flowd_tc_apply_executor_available(void)
{
    return access(FLOWD_TC_BINARY, X_OK) == 0 && access(FLOWD_IP_BINARY, X_OK) == 0;
}

int flowd_runtime_db_probe(int *present, int *openable, int *populated)
{
    static const char *const snapshot_tables[] = {
        "flowd_wan_counters", "flowd_host_counters", "flowd_rule_hits",
        "flowd_active_apps", "flowd_wan_health_status", "flowd_wan_health_samples",
        "flowd_global_category_counters", "flowd_wan_category_counters",
        "flowd_dpi_cache", "flow_dpi_cache_snapshot", "flowd_quota_state",
        "flow_quota_state", "flowd_risk_cache"
    };
    sqlite3 *db = NULL;
    sqlite3_stmt *st = NULL;
    size_t i;
    int rc;

    if (present)
        *present = 0;
    if (openable)
        *openable = 0;
    if (populated)
        *populated = 0;
    if (access(FLOWD_DEFAULT_FLOW_DB_PATH, F_OK) != 0)
        return 0;
    if (present)
        *present = 1;
    rc = sqlite3_open_v2(FLOWD_DEFAULT_FLOW_DB_PATH, &db,
                         SQLITE_OPEN_READONLY, NULL);
    if (rc != SQLITE_OK) {
        if (db)
            sqlite3_close(db);
        return -1;
    }
    if (openable)
        *openable = 1;
    for (i = 0; i < sizeof(snapshot_tables) / sizeof(snapshot_tables[0]); i++) {
        char sql[160];
        int exists = 0;

        if (sqlite3_prepare_v2(db,
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1 LIMIT 1",
            -1, &st, NULL) != SQLITE_OK)
            break;
        sqlite3_bind_text(st, 1, snapshot_tables[i], -1, SQLITE_STATIC);
        rc = sqlite3_step(st);
        exists = rc == SQLITE_ROW;
        sqlite3_finalize(st);
        st = NULL;
        if (!exists)
            continue;
        if (snprintf(sql, sizeof(sql), "SELECT 1 FROM %s LIMIT 1",
                     snapshot_tables[i]) >= (int)sizeof(sql))
            continue;
        if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
            continue;
        rc = sqlite3_step(st);
        sqlite3_finalize(st);
        st = NULL;
        if (rc == SQLITE_ROW) {
            if (populated)
                *populated = 1;
            break;
        }
    }
    if (st)
        sqlite3_finalize(st);
    sqlite3_close(db);
    return 0;
}

static void flowd_tc_contract_reason(const struct flowd_settings *settings,
                                     const struct flowd_tc_runtime_state *state,
                                     char *reason, size_t reason_len)
{
    if (settings && !settings->enabled) {
        snprintf(reason, reason_len, "flow_engine_disabled");
    } else if (!settings || strcmp(settings->apply_mode, "managed")) {
        snprintf(reason, reason_len, "flowd_apply_mode_disabled");
    } else if (state && state->present && state->reason[0]) {
        snprintf(reason, reason_len, "%s", state->reason);
    } else if (!flowd_tc_apply_executor_available()) {
        snprintf(reason, reason_len, "dataplane_apply_executor_missing");
    } else {
        snprintf(reason, reason_len, "runtime_state_missing");
    }
}

int flowd_tc_runtime_contract_state_v2(struct flowd_runtime_contract_input *input,
                                       size_t input_size, unsigned int abi_version)
{
    struct flowd_tc_runtime_state state;
    struct flowd_settings settings;
    int settings_ok;
    int managed;

    if (!input || input_size != sizeof(*input) ||
        abi_version != FLOWD_RUNTIME_CONTRACT_ABI_VERSION)
        return -1;
    settings_ok = flowd_settings_load(&settings) == 0;
    managed = settings_ok && settings.enabled &&
              !strcmp(settings.apply_mode, "managed");
    input->tc_binary_available = flowd_tc_apply_executor_available();
    input->apply_executor_available = input->tc_binary_available;
    input->runtime_readback_available = input->tc_binary_available;
    input->runtime_applied = 0;
    input->runtime_reason[0] = '\0';
    flowd_runtime_db_probe(&input->runtime_db_present,
                          &input->runtime_db_openable,
                          &input->runtime_populated);
    input->runtime_snapshot_available = input->runtime_populated;
    memset(&state, 0, sizeof(state));
    if (managed && flowd_tc_runtime_state_read(&state) == 0) {
        input->runtime_applied = state.runtime_applied;
        if (state.reason[0])
            snprintf(input->runtime_reason, sizeof(input->runtime_reason), "%s", state.reason);
    }
    if (!input->runtime_reason[0] ||
        !strcmp(input->runtime_reason, "runtime_state_missing"))
        flowd_tc_contract_reason(settings_ok ? &settings : NULL, &state,
                                 input->runtime_reason, sizeof(input->runtime_reason));
    return 0;
}

static int flowd_tc_legacy_nft_conflict(void)
{
    char *argv[] = { (char *)"/usr/sbin/nft", "list", "table", "inet",
                     "dreamingwrt_flow_qos", NULL };
    struct flowd_tc_capture capture;
    int rc = flowd_tc_run(argv, &capture);

    free(capture.data);
    return rc == 0;
}

static int flowd_tc_guard_interface(const char *ifname, const char *expected)
{
    char current[32] = "";

    if (if_nametoindex(ifname) == 0)
        return -1;
    if (flowd_tc_qdisc_kind(ifname, current, sizeof(current)) != 0)
        return -1;
    if (!strcmp(current, "noqueue") || !strcmp(current, "noop") ||
        (expected && expected[0] && !strcmp(current, expected)))
        return 0;
    return -2;
}

static int flowd_tc_plan_owns_ifname(const struct flowd_tc_plan *plan,
                                     const char *ifname)
{
    size_t i;

    if (!plan || !ifname || !ifname[0])
        return 0;
    for (i = 0; i < plan->profile_count; i++)
        if (!strcmp(plan->profiles[i].ifname, ifname))
            return 1;
    return 0;
}

static int flowd_tc_clear_plan(const struct flowd_tc_plan *plan)
{
    size_t i;

    if (!plan)
        return -1;
    for (i = 0; i < plan->profile_count; i++) {
        const struct flowd_tc_profile *p = &plan->profiles[i];
        char ifb[32];
        char kind[32] = "";
        char *del[] = { (char *)FLOWD_TC_BINARY, "qdisc", "del", "dev",
                        (char *)p->ifname, "root", NULL };

        if (p->egress && flowd_tc_qdisc_kind(p->ifname, kind, sizeof(kind)) == 0 &&
            strcmp(kind, "noqueue"))
            flowd_tc_command(del);
        if (p->ingress && flowd_tc_ifb_name(p->ifname, ifb, sizeof(ifb)) == 0)
            flowd_tc_ingress_clear(p->ifname, ifb);
    }
    return 0;
}

static int flowd_tc_apply_plan(const struct flowd_tc_plan *plan, char *phase,
                               size_t phase_len)
{
    size_t i;

    if (!plan)
        return -1;
    for (i = 0; i < plan->profile_count; i++) {
        const struct flowd_tc_profile *p = &plan->profiles[i];
        int rate = flowd_tc_rate(p->up_kbps, p->headroom_pct);
        int rc;

        if (p->egress && strcmp(p->scheduler, "none")) {
            if (p->up_kbps < 1) {
                snprintf(phase, phase_len, "tc_egress_rate_missing");
                return -1;
            }
            rc = flowd_tc_apply_qdisc(p->ifname, p->scheduler, rate,
                                      plan->qos_enabled, plan->qos_diffserv,
                                      plan->qos_ack_filter, plan->qos_fairness,
                                      plan->classes,
                                      plan->class_count);
            if (rc != 0) {
                snprintf(phase, phase_len, "tc_egress_qdisc");
                return rc;
            }
        }
        if (p->ingress && strcmp(p->scheduler, "none")) {
            char ifb[32];
            int down_rate = flowd_tc_rate(p->down_kbps, p->headroom_pct);

            if (p->down_kbps < 1 || flowd_tc_ifb_name(p->ifname, ifb, sizeof(ifb)) != 0 ||
                flowd_tc_ifb_prepare(ifb) != 0 ||
                flowd_tc_ingress_attach(p->ifname, ifb) != 0 ||
                flowd_tc_apply_qdisc(ifb, p->scheduler, down_rate,
                                     plan->qos_enabled, plan->qos_diffserv,
                                     plan->qos_ack_filter, plan->qos_fairness,
                                     plan->classes,
                                     plan->class_count) != 0) {
                snprintf(phase, phase_len, "tc_ingress_qdisc");
                return -1;
            }
        }
    }
    return 0;
}

static struct json_object *flowd_tc_readback_plan(const struct flowd_tc_plan *plan,
                                                  int *readback_ok)
{
    struct json_object *arr = json_object_new_array();
    size_t i;

    if (readback_ok)
        *readback_ok = 1;

    for (i = 0; i < plan->profile_count; i++) {
        const struct flowd_tc_profile *p = &plan->profiles[i];
        struct json_object *o = json_object_new_object();
        char ifb[32];
        struct flowd_tc_qdisc_state state;
        char expected[32] = "";
        const char *expected_diffserv = plan->qos_enabled && plan->qos_diffserv
            ? "diffserv4" : "besteffort";
        int up_rate = flowd_tc_rate(p->up_kbps, p->headroom_pct);
        int down_rate = flowd_tc_rate(p->down_kbps, p->headroom_pct);

        flowd_tc_profile_kind(p->scheduler, expected, sizeof(expected));

        json_object_object_add(o, "wan", json_object_new_string(p->wan));
        json_object_object_add(o, "ifname", json_object_new_string(p->ifname));
        json_object_object_add(o, "scheduler", json_object_new_string(p->scheduler));
        json_object_object_add(o, "qos_class_mapping",
                               json_object_new_string(!strcmp(p->scheduler, "cake") &&
                                                      plan->qos_enabled && plan->class_count
                                   ? "cake_diffserv_tins" : "native_classes"));
        if (!strcmp(p->scheduler, "cake") && plan->qos_enabled && plan->class_count)
            json_object_object_add(o, "qos_class_mapping_note",
                                   json_object_new_string(
                                       "configured classes are represented by CAKE diffserv tins; no per-class tc hierarchy is installed"));
        if (p->egress) {
            memset(&state, 0, sizeof(state));
            if (flowd_tc_qdisc_state(p->ifname, &state) != 0 ||
                strcmp(state.kind, expected) ||
                (!strcmp(expected, "cake") &&
                 (state.bandwidth_bytes != (int64_t)up_rate * 125 ||
                  strcmp(state.diffserv, expected_diffserv)))) {
                if (readback_ok)
                    *readback_ok = 0;
            }
            json_object_object_add(o, "egress_qdisc", json_object_new_string(state.kind));
            json_object_object_add(o, "egress_rate_kbps", json_object_new_int(up_rate));
            if (!strcmp(expected, "cake"))
                json_object_object_add(o, "egress_diffserv",
                                       json_object_new_string(state.diffserv));
        }
        if (p->ingress && flowd_tc_ifb_name(p->ifname, ifb, sizeof(ifb)) == 0) {
            memset(&state, 0, sizeof(state));
            if (flowd_tc_qdisc_state(ifb, &state) != 0 ||
                strcmp(state.kind, expected) ||
                (!strcmp(expected, "cake") &&
                 (state.bandwidth_bytes != (int64_t)down_rate * 125 ||
                  strcmp(state.diffserv, expected_diffserv)))) {
                if (readback_ok)
                    *readback_ok = 0;
            }
            json_object_object_add(o, "ifb", json_object_new_string(ifb));
            json_object_object_add(o, "ingress_qdisc", json_object_new_string(state.kind));
            json_object_object_add(o, "ingress_rate_kbps", json_object_new_int(down_rate));
            if (!strcmp(expected, "cake"))
                json_object_object_add(o, "ingress_diffserv",
                                       json_object_new_string(state.diffserv));
        }
        json_object_array_add(arr, o);
    }
    return arr;
}

static int flowd_tc_write_state(const struct flowd_tc_plan *plan,
                                struct json_object *desired,
                                struct json_object *readback,
                                int runtime_applied, int rollback_ok,
                                const char *phase, const char *reason,
                                const char *generation, int64_t applied_at)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *st = NULL;
    const char *desired_s = json_object_to_json_string_ext(desired, JSON_C_TO_STRING_PLAIN);
    const char *readback_s = json_object_to_json_string_ext(readback, JSON_C_TO_STRING_PLAIN);
    int rc;

    (void)plan;
    if (flowd_mkdir_p("/etc/dreamingwrt", 0755) != 0 || flowd_tc_state_db(&db, 1) != 0)
        return -1;
    sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, NULL);
    sqlite3_exec(db, "DELETE FROM flowd_tc_resources", NULL, NULL, NULL);
    if (sqlite3_prepare_v2(db,
        "INSERT INTO flowd_tc_apply_state(id,owner,runtime_applied,rollback_ok,phase,reason,generation,applied_at,desired_json,readback_json) "
        "VALUES(1,?1,?2,?3,?4,?5,?6,?7,?8,?9) ON CONFLICT(id) DO UPDATE SET owner=excluded.owner,runtime_applied=excluded.runtime_applied,rollback_ok=excluded.rollback_ok,phase=excluded.phase,reason=excluded.reason,generation=excluded.generation,applied_at=excluded.applied_at,desired_json=excluded.desired_json,readback_json=excluded.readback_json",
        -1, &st, NULL) != SQLITE_OK) {
        sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
        sqlite3_close(db);
        return -1;
    }
    sqlite3_bind_text(st, 1, FLOWD_TC_OWNER, -1, SQLITE_STATIC);
    sqlite3_bind_int(st, 2, runtime_applied);
    sqlite3_bind_int(st, 3, rollback_ok);
    sqlite3_bind_text(st, 4, phase ? phase : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 5, reason ? reason : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 6, generation ? generation : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 7, applied_at);
    sqlite3_bind_text(st, 8, desired_s ? desired_s : "{}", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 9, readback_s ? readback_s : "{}", -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc == SQLITE_DONE && runtime_applied) {
        size_t i;
        for (i = 0; i < plan->profile_count; i++) {
            const struct flowd_tc_profile *p = &plan->profiles[i];
            char ifb[32] = "";
            struct json_object *resource = json_object_array_get_idx(readback, i);

            if (p->ingress)
                flowd_tc_ifb_name(p->ifname, ifb, sizeof(ifb));
            if (sqlite3_prepare_v2(db,
                "INSERT INTO flowd_tc_resources(owner,wan,direction,ifname,ifb_name,qdisc_kind,readback_json) VALUES(?1,?2,?3,?4,?5,?6,?7)",
                -1, &st, NULL) != SQLITE_OK) {
                rc = SQLITE_ERROR;
                break;
            }
            sqlite3_bind_text(st, 1, FLOWD_TC_OWNER, -1, SQLITE_STATIC);
            sqlite3_bind_text(st, 2, p->wan, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 3, p->egress ? "egress" : "ingress", -1, SQLITE_STATIC);
            sqlite3_bind_text(st, 4, p->ifname, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 5, ifb, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 6, p->scheduler, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 7, resource ? json_object_to_json_string(resource) : "{}", -1, SQLITE_TRANSIENT);
            if (sqlite3_step(st) != SQLITE_DONE)
                rc = SQLITE_ERROR;
            sqlite3_finalize(st);
            if (rc != SQLITE_DONE)
                break;
        }
    }
    if (rc == SQLITE_DONE)
        sqlite3_exec(db, "COMMIT", NULL, NULL, NULL);
    else
        sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
    sqlite3_close(db);
    return rc == SQLITE_DONE ? 0 : -1;
}

struct json_object *flowd_tc_apply(const struct flowd_settings *settings)
{
    struct flowd_tc_runtime_state previous;
    struct flowd_tc_plan new_plan;
    struct flowd_tc_plan old_plan;
    struct json_object *desired = NULL;
    struct json_object *old_desired_obj = NULL;
    struct json_object *readback = NULL;
    struct json_object *resp = json_object_new_object();
    char *old_desired = NULL;
    char *old_readback = NULL;
    char phase[64] = "validate";
    char reason[128] = "";
    char generation[FLOWD_MAX_ID];
    int rollback_ok = 1;
    int applied = 0;
    int runtime_applied = 0;
    int new_plan_available = 0;
    int state_recorded = 0;

    memset(&previous, 0, sizeof(previous));
    memset(&new_plan, 0, sizeof(new_plan));
    memset(&old_plan, 0, sizeof(old_plan));
    if (!settings || !settings->enabled) {
        snprintf(reason, sizeof(reason), "flow_engine_disabled");
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "requested", json_object_new_boolean(1));
        json_object_object_add(resp, "applied", json_object_new_boolean(0));
        json_object_object_add(resp, "runtime_applied", json_object_new_boolean(0));
        json_object_object_add(resp, "runtime_reason", json_object_new_string(reason));
        json_object_object_add(resp, "phase", json_object_new_string("guard"));
        return resp;
    }
    if (strcmp(settings->apply_mode, "managed")) {
        snprintf(reason, sizeof(reason), "flowd_apply_mode_disabled");
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "requested", json_object_new_boolean(1));
        json_object_object_add(resp, "applied", json_object_new_boolean(0));
        json_object_object_add(resp, "runtime_applied", json_object_new_boolean(0));
        json_object_object_add(resp, "runtime_reason", json_object_new_string(reason));
        json_object_object_add(resp, "phase", json_object_new_string("guard"));
        return resp;
    }
    desired = flowd_tc_plan_from_config();
    {
        sqlite3 *db = NULL;

        if (flowd_tc_state_db(&db, 0) == 0) {
            flowd_tc_state_read_db(db, &previous, &old_desired, &old_readback);
            sqlite3_close(db);
        }
    }
    if (old_desired) {
        old_desired_obj = json_tokener_parse(old_desired);
        if (old_desired_obj && flowd_tc_plan_load(old_desired_obj, &old_plan) != 0) {
            json_object_put(old_desired_obj);
            old_desired_obj = NULL;
        }
    }
    if (flowd_tc_plan_load(desired, &new_plan) != 0) {
        snprintf(reason, sizeof(reason), "tc_config_invalid");
        goto failed;
    }
    new_plan_available = 1;
    if (!flowd_tc_apply_executor_available()) {
        snprintf(phase, sizeof(phase), "executor");
        snprintf(reason, sizeof(reason), "dataplane_apply_executor_missing");
        goto failed;
    }
    if (flowd_tc_legacy_nft_conflict()) {
        snprintf(phase, sizeof(phase), "legacy_conflict");
        snprintf(reason, sizeof(reason), "legacy_nft_table_conflict");
        goto failed;
    }
    if (new_plan.qos_enabled && new_plan.profile_count == 0) {
        snprintf(reason, sizeof(reason), "tc_wan_capacity_required_for_qos");
        goto failed;
    }
    if (new_plan.qos_enabled && strcmp(new_plan.qos_scheduler, "htb") &&
        strcmp(new_plan.qos_scheduler, "cake")) {
        snprintf(reason, sizeof(reason), "tc_qos_scheduler_unsupported");
        goto failed;
    }
    if (new_plan.qos_enabled && !strcmp(new_plan.qos_scheduler, "cake")) {
        for (size_t i = 0; i < new_plan.profile_count; i++) {
            if (strcmp(new_plan.profiles[i].scheduler, "cake")) {
                snprintf(reason, sizeof(reason), "tc_qos_scheduler_mismatch");
                goto failed;
            }
        }
    }
    for (size_t i = 0; i < new_plan.profile_count; i++) {
        const struct flowd_tc_profile *p = &new_plan.profiles[i];
        char expected[32] = "";
        int guard;

        if (flowd_tc_profile_kind(p->scheduler, expected, sizeof(expected)) != 0 ||
            (p->egress && flowd_tc_guard_interface(p->ifname, expected) == -1)) {
            snprintf(reason, sizeof(reason), "tc_interface_unavailable");
            goto failed;
        }
        guard = p->egress ? flowd_tc_guard_interface(p->ifname, expected) : 0;
        if (guard == -2 &&
            !(previous.present && previous.runtime_applied && old_desired_obj &&
              flowd_tc_plan_owns_ifname(&old_plan, p->ifname))) {
            snprintf(reason, sizeof(reason), "tc_existing_qdisc_ownership_conflict");
            goto failed;
        }
    }
    if (previous.present && previous.runtime_applied && old_desired &&
        !strcmp(old_desired, json_object_to_json_string_ext(
            desired, JSON_C_TO_STRING_PLAIN))) {
        int readback_ok = 0;

        readback = flowd_tc_readback_plan(&new_plan, &readback_ok);
        if (readback && readback_ok &&
            json_object_array_length(readback) == new_plan.profile_count) {
            json_object_object_add(resp, "ok", json_object_new_boolean(1));
            json_object_object_add(resp, "requested", json_object_new_boolean(1));
            json_object_object_add(resp, "applied", json_object_new_boolean(1));
            json_object_object_add(resp, "changed", json_object_new_boolean(0));
            json_object_object_add(resp, "runtime_applied", json_object_new_boolean(1));
            json_object_object_add(resp, "runtime_reason",
                                   json_object_new_string("tc_readback_ok"));
            json_object_object_add(resp, "phase", json_object_new_string("unchanged"));
            json_object_object_add(resp, "generation",
                                   json_object_new_string(previous.generation));
            json_object_object_add(resp, "resources", readback);
            json_object_object_add(resp, "source", json_object_new_string(FLOWD_TC_OWNER));
            json_object_put(desired);
            json_object_put(old_desired_obj);
            free(old_desired);
            free(old_readback);
            return resp;
        }
        if (readback) {
            json_object_put(readback);
            readback = NULL;
        }
    }
    if (old_desired_obj)
        flowd_tc_clear_plan(&old_plan);
    if (flowd_tc_apply_plan(&new_plan, phase, sizeof(phase)) != 0)
        goto rollback;
    {
        int readback_ok = 0;

        readback = flowd_tc_readback_plan(&new_plan, &readback_ok);
        if (!readback || !readback_ok ||
            json_object_array_length(readback) != new_plan.profile_count) {
            snprintf(reason, sizeof(reason), "tc_readback_failed");
            goto rollback;
        }
    }
    flowd_make_id("tc-apply", generation, sizeof(generation));
    if (flowd_tc_write_state(&new_plan, desired, readback, 1, 1, "applied", "tc_readback_ok",
                             generation, flowd_now_s()) != 0) {
        snprintf(reason, sizeof(reason), "runtime_state_write_failed");
        goto rollback;
    }
    state_recorded = 1;
    applied = 1;
    runtime_applied = 1;
    json_object_object_add(resp, "ok", json_object_new_boolean(1));
    json_object_object_add(resp, "requested", json_object_new_boolean(1));
    json_object_object_add(resp, "applied", json_object_new_boolean(1));
    json_object_object_add(resp, "changed", json_object_new_boolean(1));
    json_object_object_add(resp, "runtime_applied", json_object_new_boolean(1));
    json_object_object_add(resp, "runtime_reason", json_object_new_string("tc_readback_ok"));
    json_object_object_add(resp, "phase", json_object_new_string("readback"));
    json_object_object_add(resp, "generation", json_object_new_string(generation));
    json_object_object_add(resp, "resources", readback);
    json_object_object_add(resp, "source", json_object_new_string(FLOWD_TC_OWNER));
    json_object_put(desired);
    json_object_put(old_desired_obj);
    free(old_desired);
    free(old_readback);
    return resp;

rollback:
    if (readback) {
        json_object_put(readback);
        readback = NULL;
    }
    if (new_plan_available)
        flowd_tc_clear_plan(&new_plan);
    if (old_desired_obj) {
        struct json_object *rollback_readback = NULL;
        int readback_ok = 0;

        if (flowd_tc_apply_plan(&old_plan, phase, sizeof(phase)) != 0) {
            rollback_ok = 0;
        } else {
            rollback_readback = flowd_tc_readback_plan(&old_plan, &readback_ok);
            rollback_ok = rollback_readback && readback_ok;
            runtime_applied = previous.runtime_applied && rollback_ok;
        }
        if (!rollback_readback)
            rollback_readback = json_object_new_array();
        flowd_make_id("tc-rollback", generation, sizeof(generation));
        state_recorded = flowd_tc_write_state(
            &old_plan, old_desired_obj, rollback_readback, runtime_applied,
            rollback_ok, phase, reason[0] ? reason : "tc_apply_failed",
            generation, flowd_now_s()) == 0;
        json_object_put(rollback_readback);
    }
    if (!reason[0])
        snprintf(reason, sizeof(reason), "tc_apply_failed");
    if (!old_desired_obj) {
        struct json_object *empty = json_object_new_object();

        flowd_make_id("tc-rollback", generation, sizeof(generation));
        state_recorded = flowd_tc_write_state(
            &new_plan, desired, empty, 0, rollback_ok, phase, reason,
            generation, flowd_now_s()) == 0;
        json_object_put(empty);
    }
failed:
    if (!state_recorded && desired) {
        struct json_object *empty = json_object_new_object();

        flowd_make_id("tc-failed", generation, sizeof(generation));
        state_recorded = flowd_tc_write_state(
            &new_plan, desired, empty, 0, rollback_ok, phase,
            reason[0] ? reason : "tc_apply_failed", generation,
            flowd_now_s()) == 0;
        json_object_put(empty);
    }
    json_object_object_add(resp, "ok", json_object_new_boolean(0));
    json_object_object_add(resp, "requested", json_object_new_boolean(1));
    json_object_object_add(resp, "applied", json_object_new_boolean(applied));
    json_object_object_add(resp, "runtime_applied", json_object_new_boolean(runtime_applied));
    json_object_object_add(resp, "runtime_reason", json_object_new_string(reason[0] ? reason : "tc_apply_failed"));
    json_object_object_add(resp, "phase", json_object_new_string(phase));
    json_object_object_add(resp, "rollback_ok", json_object_new_boolean(rollback_ok));
    json_object_object_add(resp, "source", json_object_new_string(FLOWD_TC_OWNER));
    json_object_put(desired);
    json_object_put(old_desired_obj);
    free(old_desired);
    free(old_readback);
    return resp;
}

int flowd_tc_runtime_json_add(sqlite3 *db, struct json_object *response,
                              struct json_object *tables, struct json_object *summary,
                              struct json_object *errors, int *ok, int limit)
{
    sqlite3_stmt *st = NULL;
    struct flowd_tc_runtime_state state;
    struct json_object *apply = json_object_new_object();
    struct json_object *resources = json_object_new_array();
    struct json_object *resource_rows = json_object_new_array();
    struct json_object *readback = NULL;
    char *readback_s = NULL;
    int count = 0;

    if (!db || !response || !tables || !summary || !ok)
        return -1;
    if (sqlite3_prepare_v2(db,
        "SELECT runtime_applied,rollback_ok,phase,reason,generation,applied_at,readback_json FROM flowd_tc_apply_state WHERE id=1",
        -1, &st, NULL) != SQLITE_OK || sqlite3_step(st) != SQLITE_ROW) {
        if (st)
            sqlite3_finalize(st);
        json_object_object_add(tables, "flowd_tc_apply_state", json_object_new_boolean(0));
        json_object_object_add(summary, "tc_apply", json_object_new_int(0));
        return 0;
    }
    memset(&state, 0, sizeof(state));
    state.present = 1;
    state.runtime_applied = sqlite3_column_int(st, 0);
    state.rollback_ok = sqlite3_column_int(st, 1);
    snprintf(state.phase, sizeof(state.phase), "%s", flowd_sqlite_text(st, 2, ""));
    snprintf(state.reason, sizeof(state.reason), "%s", flowd_sqlite_text(st, 3, ""));
    snprintf(state.generation, sizeof(state.generation), "%s", flowd_sqlite_text(st, 4, ""));
    state.applied_at = sqlite3_column_int64(st, 5);
    readback_s = strdup(flowd_sqlite_text(st, 6, "{}"));
    sqlite3_finalize(st);
    readback = readback_s ? json_tokener_parse(readback_s) : NULL;
    if (readback && json_object_is_type(readback, json_type_array)) {
        json_object_put(resources);
        resources = json_object_get(readback);
    }
    json_object_put(readback);
    free(readback_s);
    json_object_object_add(apply, "owner", json_object_new_string(FLOWD_TC_OWNER));
    json_object_object_add(apply, "runtime_applied", json_object_new_boolean(state.runtime_applied));
    json_object_object_add(apply, "rollback_ok", json_object_new_boolean(state.rollback_ok));
    json_object_object_add(apply, "phase", json_object_new_string(state.phase));
    json_object_object_add(apply, "reason", json_object_new_string(state.reason));
    json_object_object_add(apply, "generation", json_object_new_string(state.generation));
    json_object_object_add(apply, "applied_at", json_object_new_int64(state.applied_at));
    json_object_object_add(apply, "resources", resources);
    json_object_object_add(response, "tc_apply", apply);
    json_object_object_add(tables, "flowd_tc_apply_state", json_object_new_boolean(1));
    if (sqlite3_prepare_v2(db,
        "SELECT id,wan,direction,ifname,ifb_name,qdisc_kind,readback_json FROM flowd_tc_resources ORDER BY id LIMIT ?1",
        -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_int(st, 1, limit > 0 ? limit : 100);
        while (sqlite3_step(st) == SQLITE_ROW) {
            struct json_object *o = json_object_new_object();
            struct json_object *rb = json_tokener_parse(flowd_sqlite_text(st, 6, "{}"));

            json_object_object_add(o, "id", json_object_new_int(sqlite3_column_int(st, 0)));
            json_object_object_add(o, "wan", json_object_new_string(flowd_sqlite_text(st, 1, "")));
            json_object_object_add(o, "direction", json_object_new_string(flowd_sqlite_text(st, 2, "")));
            json_object_object_add(o, "ifname", json_object_new_string(flowd_sqlite_text(st, 3, "")));
            json_object_object_add(o, "ifb_name", json_object_new_string(flowd_sqlite_text(st, 4, "")));
            json_object_object_add(o, "qdisc_kind", json_object_new_string(flowd_sqlite_text(st, 5, "")));
            json_object_object_add(o, "readback", rb ? rb : json_object_new_object());
            json_object_array_add(resource_rows, o);
            count++;
        }
        sqlite3_finalize(st);
    } else {
        *ok = 0;
        if (errors)
            json_object_array_add(errors, json_object_new_string("flowd_tc_resources_unavailable"));
    }
    json_object_object_add(response, "tc_resources", resource_rows);
    json_object_object_add(summary, "tc_resources", json_object_new_int(count));
    return 0;
}
